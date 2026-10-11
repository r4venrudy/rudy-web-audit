"""Context-aware hardening heuristics; findings are not exploit claims."""

import re
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlsplit

from .models import Check, Hop


def headers(hop: Hop, name: str) -> list[str]:
    return [value for key, value in hop.headers if key.lower() == name.lower()]


def csp_policies(values: list[str]) -> list[dict[str, list[str]]]:
    policies = []
    for value in values:
        for raw_policy in re.split(r",(?=\s*[a-zA-Z-]+(?:\s|;|$))", value):
            directives = {}
            for item in raw_policy.split(";"):
                tokens = item.split()
                if tokens:
                    directives.setdefault(tokens[0].lower(), tokens[1:])
            policies.append(directives)
    return policies


def cookies(hop: Hop) -> list[dict]:
    result = []
    for index, value in enumerate(headers(hop, "set-cookie"), 1):
        jar = SimpleCookie()
        try:
            jar.load(value)
        except CookieError:
            pass
        if not jar:
            result.append({"name": f"unparsed-cookie-{index}", "parsed": False})
        for name, morsel in jar.items():
            result.append({"name": name, "parsed": True, "secure": bool(morsel["secure"]),
                           "httponly": bool(morsel["httponly"]), "samesite": morsel["samesite"].lower(),
                           "path": morsel["path"], "domain": morsel["domain"]})
    return result


def inspect_hop(hop: Hop, index: int, final: bool) -> list[Check]:
    checks = []

    def add(rule, title, status, severity, evidence, recommendation=""):
        checks.append(Check(rule, title, status, severity, evidence, recommendation, index))

    https = urlsplit(hop.url).scheme == "https"
    if hop.tls:
        add("TLS.VERIFIED", "Verified TLS connection", "pass", "high", f"{hop.tls['version']} / {hop.tls['cipher']}")
        remaining = hop.tls.get("days_remaining")
        if remaining is not None:
            add("TLS.EXPIRY", "Certificate lifetime", "fail" if remaining < 7 else "warn" if remaining < 30 else "pass",
                "high" if remaining < 7 else "medium", f"{remaining} complete days remain.",
                "Renew the certificate and verify automatic renewal before expiry." if remaining < 30 else "")

    for cookie in cookies(hop):
        name = cookie["name"]
        if not cookie["parsed"]:
            add("COOKIE.PARSE", "Cookie could not be parsed", "warn", "low", name,
                "Review the Set-Cookie syntax. Cookie values are not included in reports.")
            continue
        add("COOKIE.SECURE", "Cookie Secure attribute", "pass" if cookie["secure"] else "fail", "medium", name,
            "Set Secure for cookies that must only travel over HTTPS.")
        add("COOKIE.HTTPONLY", "Cookie JavaScript access", "pass" if cookie["httponly"] else "warn", "low", name,
            "Use HttpOnly for session cookies; application-readable cookies may intentionally omit it.")
        same = cookie["samesite"]
        add("COOKIE.SAMESITE", "Cookie SameSite attribute", "pass" if same in {"lax", "strict", "none"} else "warn",
            "low", f"{name}: {same or 'unspecified'}", "Choose an explicit SameSite policy appropriate to the application.")
        if same == "none" and not cookie["secure"]:
            add("COOKIE.NONE_SECURE", "SameSite=None requires Secure", "fail", "medium", name, "Add Secure to the cookie.")
        if name.startswith("__Secure-") and (not cookie["secure"] or not https):
            add("COOKIE.PREFIX", "Invalid __Secure- cookie", "fail", "medium", name,
                "Set __Secure- cookies over HTTPS with Secure.")
        if name.startswith("__Host-") and (not cookie["secure"] or not https or cookie["path"] != "/" or cookie["domain"]):
            add("COOKIE.PREFIX", "Invalid __Host- cookie", "fail", "medium", name,
                "Use HTTPS, Secure, Path=/, and no Domain attribute for __Host- cookies.")
        if not https:
            add("COOKIE.HTTP", "Cookie set over plaintext HTTP", "fail", "high", name,
                "Set cookies only after the redirect to HTTPS.")

    if not final:
        return checks

    add("HTTP.HTTPS", "Final response uses HTTPS", "pass" if https else "fail", "high",
        "HTTPS" if https else "Plaintext HTTP", "Serve the site over HTTPS and redirect HTTP entry points.")
    if hop.status >= 400:
        add("HTTP.STATUS", "Final response is an error page", "warn", "medium", f"HTTP {hop.status}",
            "Check the intended page; error and access-denied responses can use different headers.")

    if https:
        values = headers(hop, "strict-transport-security")
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*\"?(\d+)\"?\s*(?:;|$)", values[0], re.I) if values else None
        age = int(match.group(1)) if match else 0
        add("HEADER.HSTS", "HTTP Strict Transport Security", "pass" if age >= 31536000 else "warn" if age else "fail",
            "medium", f"max-age={age}" if match else "Missing, invalid, or disabled HSTS.",
            "Set a positive HSTS max-age; one year is a common long-term goal. Assess subdomains before includeSubDomains.")

    content_type = ", ".join(headers(hop, "content-type")).lower()
    html = "text/html" in content_type or "application/xhtml+xml" in content_type
    enforcing = csp_policies(headers(hop, "content-security-policy"))
    if html:
        restricted = any(policy.get("script-src") or policy.get("default-src") for policy in enforcing)
        report_only = bool(headers(hop, "content-security-policy-report-only"))
        add("HEADER.CSP", "Enforced script policy", "pass" if restricted else "fail", "medium",
            "Enforcing script/default source policy found." if restricted else
            "Report-only policy does not enforce restrictions." if report_only else "No effective script/default source restriction found.",
            "Deploy an enforcing CSP after testing in report-only mode. Prefer nonces or hashes for scripts.")
        for policy in enforcing:
            for directive in ("script-src", "script-src-elem"):
                sources = policy.get(directive, policy.get("script-src", policy.get("default-src", [])))
                dynamic = any(item.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for item in sources)
                risky = sorted(set(sources) & {"*", "http:", "https:", "data:", "'unsafe-eval'"})
                if "'unsafe-inline'" in sources and not dynamic:
                    risky.append("'unsafe-inline'")
                if risky:
                    add("CSP.BROAD_SCRIPT", "Broad CSP script sources", "warn", "medium", f"{directive}: {', '.join(risky)}",
                        "Review broad script sources. Multiple CSP policies intersect; this is a policy-level heuristic.")
        framed = any(policy.get("frame-ancestors") and "*" not in policy["frame-ancestors"] for policy in enforcing)
        xfo = [value.strip().upper() for value in headers(hop, "x-frame-options")]
        add("HEADER.FRAMING", "Framing protection", "pass" if framed or any(v in {"DENY", "SAMEORIGIN"} for v in xfo) else "warn",
            "medium", "Restrictive frame-ancestors or X-Frame-Options found." if framed or xfo else "No framing restriction found.",
            "Use CSP frame-ancestors or X-Frame-Options where the page should not be embedded.")
    else:
        add("HEADER.CSP", "HTML-specific policy checks", "info", "info", "Response is not declared as HTML; script and framing checks skipped.")

    nosniff = any(value.strip().lower() == "nosniff" for value in headers(hop, "x-content-type-options"))
    add("HEADER.NOSNIFF", "MIME sniffing protection", "pass" if nosniff else "warn", "low",
        "nosniff" if nosniff else "X-Content-Type-Options: nosniff not found.", "Add X-Content-Type-Options: nosniff.")

    referrers = [token.strip().lower() for value in headers(hop, "referrer-policy") for token in value.split(",")]
    recognized = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin",
                  "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
    effective = next((token for token in reversed(referrers) if token in recognized), None)
    safe = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    add("HEADER.REFERRER", "Referrer privacy policy", "pass" if effective in safe else "warn", "low",
        effective or "No explicit recognized policy; browser defaults vary.",
        "Choose an explicit Referrer-Policy, such as strict-origin-when-cross-origin.")

    for value in headers(hop, "access-control-allow-origin"):
        if value.strip() == "*":
            add("HEADER.CORS", "Public cross-origin response", "info", "info", "Access-Control-Allow-Origin: *",
                "This can be intentional for public resources; it does not establish a data exposure vulnerability.")
    if headers(hop, "server") or headers(hop, "x-powered-by"):
        add("HEADER.DISCLOSURE", "Technology banner exposed", "info", "info", "Server or X-Powered-By header present.",
            "Consider removing unnecessary version banners. A banner alone is not a vulnerability.")
    return checks


def score_checks(checks: list[Check]) -> tuple[int, str]:
    penalties = {"critical": 35, "high": 20, "medium": 10, "low": 3, "info": 0}
    by_rule = {}
    for check in checks:
        penalty = penalties[check.severity] if check.status == "fail" else penalties[check.severity] / 2 if check.status == "warn" else 0
        by_rule[check.id] = max(by_rule.get(check.id, 0), penalty)
    score = max(0, round(100 - sum(by_rule.values())))
    grade = next(grade for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")) if score >= threshold)
    return score, grade
