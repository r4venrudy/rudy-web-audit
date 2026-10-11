from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from urllib.parse import urljoin, urlsplit

from .models import Audit, Check
from .rules import cookies, headers, inspect_hop, score_checks
from .transport import AuditError, display_url, fetch, normalize_url, target_id

REDIRECTS = {301, 302, 303, 307, 308}
EXPORT_HEADERS = {"content-type", "content-security-policy", "content-security-policy-report-only",
                  "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy",
                  "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy",
                  "cross-origin-embedder-policy", "access-control-allow-origin", "access-control-allow-credentials",
                  "server", "x-powered-by", "location"}


def sanitized_headers(hop) -> list[tuple[str, str]]:
    result = []
    for name, value in hop.headers:
        lower = name.lower()
        if lower not in EXPORT_HEADERS:
            continue
        if lower == "location":
            try:
                value = display_url(normalize_url(urljoin(hop.url, value)))
            except AuditError:
                value = "[invalid location omitted]"
        elif lower in {"content-security-policy", "content-security-policy-report-only"}:
            # CSP nonces and reporting endpoints can contain transient identifiers.
            value = "[policy omitted; see derived checks]"
        result.append((name, value))
    for cookie in cookies(hop):
        flags = [flag for flag in ("secure", "httponly") if cookie.get(flag)]
        if cookie.get("samesite"):
            flags.append("samesite=" + cookie["samesite"])
        result.append(("Set-Cookie", f"{cookie['name']}=[redacted]" + ("; " + "; ".join(flags) if flags else "")))
    return result


def scan(target: str, timeout: float = 10, max_redirects: int = 5, allow_private: bool = False) -> Audit:
    try:
        current = normalize_url(target)
        audit = Audit(display_url(current), target_id(current))
    except AuditError as exc:
        return Audit("[invalid target]", target_id(target), error=str(exc))
    visited = set()
    try:
        for index in range(max_redirects + 1):
            if current in visited:
                raise AuditError("Redirect loop detected.")
            visited.add(current)
            hop = fetch(current, timeout, allow_private)
            location = headers(hop, "location")
            is_redirect = hop.status in REDIRECTS and bool(location)
            audit.checks.extend(inspect_hop(hop, index, final=not is_redirect))
            audit.hops.append(replace(hop, url=display_url(hop.url), headers=sanitized_headers(hop)))
            if not is_redirect:
                if hop.status in REDIRECTS:
                    raise AuditError("Redirect response has no Location header.")
                audit.score, audit.grade = score_checks(audit.checks)
                return audit
            if index == max_redirects:
                raise AuditError("Redirect limit reached.")
            next_url = normalize_url(urljoin(current, location[0]))
            if urlsplit(current).scheme == "https" and urlsplit(next_url).scheme == "http":
                audit.checks.append(Check("HTTP.DOWNGRADE", "HTTPS redirects to HTTP", "fail", "high",
                                          "Redirect lowers transport security.", "Redirect only to HTTPS destinations.", index))
            if urlsplit(current).hostname != urlsplit(next_url).hostname:
                audit.checks.append(Check("HTTP.CROSS_HOST", "Cross-host redirect", "info", "info",
                                          f"{urlsplit(current).hostname} -> {urlsplit(next_url).hostname}", hop=index))
            current = next_url
    except AuditError as exc:
        audit.error = str(exc)
    return audit


def scan_many(targets: list[str], workers: int = 4, **options) -> list[Audit]:
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(lambda value: scan(value, **options), targets))
