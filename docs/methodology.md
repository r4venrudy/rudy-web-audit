# Evidence and methodology

Each scan starts with a normalized HTTP/HTTPS URL. The tool resolves the hostname, rejects any non-public address unless explicitly permitted, then connects directly to a validated address. TLS wraps that same connection with hostname and chain verification; the minimum protocol is TLS 1.2. Redirect destinations repeat validation and resolution independently. Proxy environment variables are not used.

The request is GET with a declared user agent. Only response headers are consumed. No authentication headers, persistent cookies or browser state are supplied. A GET can have server-side effects if the target application implements it that way.

## Rules

| Family | Observations |
| :--- | :--- |
| `TLS.*` | Verified connection metadata and certificate remaining lifetime |
| `HTTP.*` | Final transport, status, cross-host redirects and transport downgrade |
| `HEADER.*` | HSTS, enforcing script CSP, framing, nosniff, referrer policy, CORS and technology banners |
| `CSP.*` | Broad script-source constructs in individual enforcing policies, and nonce policies without `base-uri` |
| `CORS.*` | Credentialed access granted to the `null` origin, which sandboxed frames and local files can claim |
| `COOKIE.*` | Parsing, Secure, HttpOnly, SameSite, `None`/Secure, prefix constraints, plaintext setting and (informational) subdomain-wide `Domain` scope |

HSTS passes the long-term heuristic at a one-year max-age. A positive shorter policy is a warning; missing, invalid or zero-age policies fail the heuristic. The tool does not check browser preload membership or recommend includeSubDomains without evaluating the application.

CSP report-only headers do not enforce restrictions. Script checks use first-occurrence directive parsing and source fallback. The inline-script heuristic recognizes nonce/hash sources. CSP grammar and the interactions of multiple enforcing policies are not fully simulated; broad sources are review observations rather than exploit claims.

HttpOnly may be intentionally absent on application-readable cookies. CORS wildcard origins and technology banners are informational. The tool does not infer a data leak from a public CORS response.

## Score

Scores start at 100. Failure penalties are critical 35, high 20, medium 10 and low 3; warning penalties are half those values, and informational/pass observations have no penalty. Only the largest penalty per rule ID is applied across all hops/cookies. The result is rounded to an integer and clamped at zero.

Grades: A ≥90; B ≥80; C ≥70; D ≥60; F <60. Incomplete scans are **Unrated**, with no numeric score. Scores measure these limited checks only; an API skipping HTML rules can score differently from an HTML page.

## Comparison

Targets use a SHA-256 hash of the complete normalized URL so query values can be omitted from exported display URLs. A changed query changes target identity. Checks are matched by rule ID and hop index, with cookie names added for cookie rules. Duplicate checks are grouped by worst state. A transition from pass/info to warning/failure or from warning to failure is a regression. Severity increases within the same adverse state also count.

Findings that disappear are reported as improvements in observations; a response-type or redirect-chain change can affect comparability. Review the evidence alongside the diff. Targets with network errors are incomparable, and target coverage changes prevent a successful regression gate.

## Sources

- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Python ssl documentation](https://docs.python.org/3/library/ssl.html)
- [Python http.client documentation](https://docs.python.org/3/library/http.client.html)

These sources inform the checks; this project is independent and does not claim OWASP certification or full compliance with a security standard.
