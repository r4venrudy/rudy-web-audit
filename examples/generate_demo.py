"""Generate fictional report artifacts; makes no network requests."""

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rudy_web_audit.models import Audit, Hop
from rudy_web_audit.report import compare, document, html_report
from rudy_web_audit.rules import inspect_hop, score_checks
from rudy_web_audit.transport import target_id


def example(url, extra, kind="text/html"):
    hop = Hop(url, 200, "192.0.2.10", 84.3,
              [("Content-Type", kind), ("X-Content-Type-Options", "nosniff"),
               ("Strict-Transport-Security", "max-age=31536000"),
               ("Referrer-Policy", "strict-origin-when-cross-origin"), *extra],
              {"verified": True, "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
               "expires_at": "2030-01-01T00:00:00+00:00", "days_remaining": 70, "sha256": "a" * 64})
    checks = inspect_hop(hop, 0, True)
    score, grade = score_checks(checks)
    from rudy_web_audit.scanner import sanitized_headers
    hop.headers = sanitized_headers(hop)
    return Audit(url, target_id(url), [hop], checks, score=score, grade=grade)


def main():
    application = example("https://app.example.test/", [("Content-Security-Policy", "script-src * 'unsafe-inline'; frame-ancestors 'self'"),
                                                       ("Set-Cookie", "session=fictional; SameSite=None")])
    api = example("https://api.example.test/status", [("Access-Control-Allow-Origin", "*")], "application/json")
    current = document([application, api])
    current["generated_at"] = "2026-10-11T12:00:00+02:00 (synthetic example)"
    previous = copy.deepcopy(current)
    for check in previous["targets"][0]["checks"]:
        if check["status"] in {"warn", "fail"}:
            check["status"] = "pass"
    current["comparison"] = compare(previous, current)
    folder = Path(__file__).resolve().parent
    (folder / "demo.json").write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    (folder / "demo.html").write_text(html_report(current), encoding="utf-8")
    print("Generated synthetic examples/demo.json and examples/demo.html")


if __name__ == "__main__":
    main()
