import copy
import io
import json
import os
import socket
import ssl
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from rudy_web_audit.cli import main, parser
from rudy_web_audit.models import Audit, Check, Hop
from rudy_web_audit.report import compare, document, html_report, load_document, sarif, text_report
from rudy_web_audit.rules import csp_policies, inspect_hop, score_checks
from rudy_web_audit.scanner import scan, scan_many
from rudy_web_audit.transport import AuditError, display_url, normalize_url, resolve


def page(extra=(), url="https://example.com/", content_type="text/html"):
    return Hop(url, 200, "93.184.216.34", 1, [("Content-Type", content_type), *extra],
               {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "days_remaining": 60,
                "expires_at": "2030-01-01T00:00:00+00:00", "verified": True, "sha256": "a" * 64})


def check(hop, rule):
    return next(item for item in inspect_hop(hop, 0, True) if item.id == rule)


class URLTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(normalize_url("EXAMPLE.com:443/a#fragment"), "https://example.com/a")

    def test_unicode_host_and_path(self):
        self.assertEqual(normalize_url("https://bücher.example/é"), "https://xn--bcher-kva.example/%C3%A9")

    def test_ipv6(self):
        self.assertEqual(normalize_url("http://[::1]:8000/"), "http://[::1]:8000/")

    def test_reject_unsafe_input(self):
        for value in ("ftp://example.com", "https://u:p@example.com", "https://example.com:0", "https://example.com:65536",
                      "http://[::1", "https://example.com/\r\nX-Test:yes", "https://-bad.example", "https://example.com\\evil"):
            with self.subTest(value=value), self.assertRaises(AuditError):
                normalize_url(value)

    def test_redact_query(self):
        exported = display_url("https://example.com/path?token=private-value&x=second&blank=")
        self.assertNotIn("private-value", exported)
        self.assertNotIn("second", exported)
        self.assertIn("token=", exported)

    def test_private_and_mapped_addresses_blocked(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "224.0.0.1"):
            with self.subTest(address=address), patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 80))]):
                with self.assertRaises(AuditError):
                    resolve("test.example", 80)

    def test_mixed_dns_blocked(self):
        answers = [(2, 1, 6, "", ("8.8.8.8", 80)), (2, 1, 6, "", ("127.0.0.1", 80))]
        with patch("socket.getaddrinfo", return_value=answers):
            with self.assertRaises(AuditError):
                resolve("test.example", 80)
            self.assertEqual(resolve("test.example", 80, True), answers)


class RuleTests(unittest.TestCase):
    def test_hsts_values(self):
        for value, status in (("max-age=31536000; includeSubDomains", "pass"), ("max-age=100", "warn"),
                              ("max-age=0", "fail"), ("max-age=oops", "fail"), ('max-age="31536000"', "pass")):
            with self.subTest(value=value):
                self.assertEqual(check(page([("Strict-Transport-Security", value)]), "HEADER.HSTS").status, status)

    def test_report_only_does_not_enforce(self):
        result = check(page([("Content-Security-Policy-Report-Only", "default-src 'self'")]), "HEADER.CSP")
        self.assertEqual(result.status, "fail")

    def test_duplicate_csp_directive_first_wins(self):
        self.assertEqual(csp_policies(["script-src 'self'; script-src *"])[0]["script-src"], ["'self'"])

    def test_frame_ancestors_wildcard_is_not_protection(self):
        self.assertEqual(check(page([("Content-Security-Policy", "frame-ancestors *")]), "HEADER.FRAMING").status, "warn")

    def test_frame_ancestors_none_is_protection(self):
        self.assertEqual(check(page([("Content-Security-Policy", "frame-ancestors 'none'")]), "HEADER.FRAMING").status, "pass")

    def test_nonce_ignores_unsafe_inline_heuristic(self):
        hop = page([("Content-Security-Policy", "script-src 'nonce-abc' 'unsafe-inline'")])
        self.assertFalse(any(item.id == "CSP.BROAD_SCRIPT" for item in inspect_hop(hop, 0, True)))

    def test_unsafe_eval_flagged_with_nonce(self):
        hop = page([("Content-Security-Policy", "script-src 'nonce-abc' 'unsafe-eval'")])
        self.assertTrue(any(item.id == "CSP.BROAD_SCRIPT" for item in inspect_hop(hop, 0, True)))

    def test_api_skips_html_checks(self):
        hop = page(content_type="application/json")
        checks = inspect_hop(hop, 0, True)
        self.assertEqual(check(hop, "HEADER.CSP").status, "info")
        self.assertFalse(any(item.id == "HEADER.FRAMING" for item in checks))

    def test_samesite_none_requires_secure(self):
        hop = page([("Set-Cookie", "sid=secret; SameSite=None")])
        self.assertEqual(check(hop, "COOKIE.NONE_SECURE").status, "fail")

    def test_host_prefix_rules(self):
        hop = page([("Set-Cookie", "__Host-session=x; Secure; Path=/; Domain=example.com")])
        self.assertEqual(check(hop, "COOKIE.PREFIX").status, "fail")

    def test_multiple_cookies_and_expires_comma(self):
        hop = page([("Set-Cookie", "one=a; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax"),
                    ("Set-Cookie", "two=b; Secure; HttpOnly; SameSite=Strict")])
        names = [item.evidence for item in inspect_hop(hop, 0, True) if item.id == "COOKIE.SECURE"]
        self.assertEqual(names, ["one", "two"])

    def test_referrer_last_recognized_value(self):
        hop = page([("Referrer-Policy", "no-referrer, unsafe-url, unknown")])
        self.assertEqual(check(hop, "HEADER.REFERRER").status, "warn")

    def test_credentialed_null_origin(self):
        hop = page([("Access-Control-Allow-Origin", "null"), ("Access-Control-Allow-Credentials", "true")])
        self.assertEqual(check(hop, "CORS.NULL_ORIGIN").status, "warn")
        hop = page([("Access-Control-Allow-Origin", "null")])
        self.assertFalse(any(item.id == "CORS.NULL_ORIGIN" for item in inspect_hop(hop, 0, True)))

    def test_nonce_policy_needs_base_uri(self):
        hop = page([("Content-Security-Policy", "script-src 'nonce-abc'")])
        self.assertEqual(check(hop, "CSP.BASE_URI").status, "warn")
        hop = page([("Content-Security-Policy", "script-src 'nonce-abc'; base-uri 'none'")])
        self.assertFalse(any(item.id == "CSP.BASE_URI" for item in inspect_hop(hop, 0, True)))

    def test_score_deduplicates_rules(self):
        finding = Check("X", "title", "fail", "high", "evidence")
        self.assertEqual(score_checks([finding, finding]), (80, "B"))

    def test_certificate_expiry(self):
        hop = page()
        hop.tls["days_remaining"] = 3
        self.assertEqual(check(hop, "TLS.EXPIRY").status, "fail")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        self.send_response(302 if path in {"/redirect", "/loop", "/external", "/bad-location", "/missing-location"} else 200)
        if path == "/redirect":
            self.send_header("Location", "/good?token=redirect-secret")
        elif path == "/loop":
            self.send_header("Location", "/loop")
        elif path == "/external":
            self.send_header("Location", "http://127.0.0.1:9/")
        elif path == "/bad-location":
            self.send_header("Location", "ftp://example.com/")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Set-Cookie", "sid=cookie-secret; Secure; HttpOnly; SameSite=Lax; Path=/")
        self.send_header("X-Unknown-Secret", "unknown-secret")
        self.end_headers()


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_real_http_and_redaction(self):
        result = scan(self.base + "/redirect?token=original-secret", allow_private=True)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.hops), 2)
        exported = json.dumps(result.to_dict())
        for secret in ("cookie-secret", "original-secret", "redirect-secret", "unknown-secret"):
            self.assertNotIn(secret, exported)

    def test_local_targets_blocked_by_default(self):
        result = scan(self.base)
        self.assertIn("Non-public", result.error)
        self.assertIsNone(result.score)

    def test_redirect_loop(self):
        self.assertIn("loop", scan(self.base + "/loop", allow_private=True).error)

    def test_redirect_limit(self):
        self.assertIn("limit", scan(self.base + "/redirect", max_redirects=0, allow_private=True).error)

    def test_bad_redirect_scheme(self):
        self.assertIn("Only http", scan(self.base + "/bad-location", allow_private=True).error)

    def test_missing_redirect_location(self):
        self.assertIn("no Location", scan(self.base + "/missing-location", allow_private=True).error)

    def test_every_redirect_is_revalidated(self):
        real_resolve = resolve
        calls = []
        def guard(host, port, allow_private=False):
            calls.append(port)
            if port == 9:
                raise AuditError("Non-public redirect blocked by fixture.")
            return real_resolve(host, port, True)
        with patch("rudy_web_audit.transport.resolve", side_effect=guard):
            result = scan(self.base + "/external")
        self.assertIn(9, calls)
        self.assertIn("blocked", result.error)

    def test_bulk_order_preserved(self):
        targets = [self.base + "/good", self.base + "/loop"]
        results = scan_many(targets, workers=2, allow_private=True)
        self.assertIsNone(results[0].error)
        self.assertIsNotNone(results[1].error)

    def test_cli_json_and_gate(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main([self.base, "--allow-private", "--format", "json", "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["schema_version"], 1)

    def test_cli_network_error_is_exit_two(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([self.base]), 2)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.data = document([Audit("https://example.com/", "stable-id", checks=[Check("HEADER.CSP", "CSP", "pass", "medium", "present")], score=100, grade="A")])

    def test_baseline_regression(self):
        newer = copy.deepcopy(self.data)
        newer["targets"][0]["checks"][0]["status"] = "fail"
        self.assertEqual(len(compare(self.data, newer)["regressions"]), 1)
        self.assertEqual(len(compare(newer, self.data)["improvements"]), 1)

    def test_failed_scan_not_treated_as_improvement(self):
        newer = copy.deepcopy(self.data)
        newer["targets"][0]["error"] = "timeout"
        newer["targets"][0]["checks"] = []
        diff = compare(self.data, newer)
        self.assertEqual(len(diff["incomparable"]), 1)
        self.assertEqual(diff["improvements"], [])

    def test_new_and_removed_targets(self):
        newer = copy.deepcopy(self.data)
        newer["targets"][0]["target_id"] = "different"
        diff = compare(self.data, newer)
        self.assertEqual(len(diff["new_targets"]), 1)
        self.assertEqual(len(diff["removed_targets"]), 1)

    def test_html_escapes_remote_input_and_template_tokens(self):
        self.data["targets"][0]["target"] = '<script>alert(1)</script>__CARDS__'
        rendered = html_report(self.data)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("__CARDS__", rendered)

    def test_text_strips_terminal_escape(self):
        self.data["targets"][0]["target"] = "evil\x1b[2J"
        self.assertNotIn("\x1b", text_report(self.data))

    def test_sarif_result_fingerprint(self):
        self.data["targets"][0]["checks"][0]["status"] = "fail"
        result = sarif(self.data)
        self.assertEqual(result["version"], "2.1.0")
        self.assertEqual(len(result["runs"][0]["results"]), 1)
        self.assertEqual(result, sarif(self.data))

    def test_invalid_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text('{"schema_version":42,"targets":[]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_document(str(path))

    def test_bad_cli_limits(self):
        for option, value in (("--timeout", "nan"), ("--timeout", "inf"), ("--workers", "0"), ("--max-redirects", "99")):
            with self.subTest(option=option, value=value), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser().parse_args([option, value])

    def test_cli_requires_targets(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main([]), 2)

    def test_regression_gate_rejects_changed_target_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text(json.dumps(self.data), encoding="utf-8")
            current = Audit("https://other.example/", "other-id", score=100, grade="A")
            with patch("rudy_web_audit.cli.scan_many", return_value=[current]), redirect_stdout(io.StringIO()):
                self.assertEqual(main(["https://other.example/", "--baseline", str(path), "--fail-on", "regression"]), 2)


class TLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = Path(__file__).resolve().parent / "fixtures"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.fixtures / "localhost-cert.pem"), str(cls.fixtures / "localhost-key.pem"))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"https://127.0.0.1:{cls.server.server_port}/good"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_untrusted_certificate_rejected(self):
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(self.fixtures / "does-not-exist.pem")}):
            result = scan(self.url, allow_private=True)
        self.assertIn("certificate verification failed", result.error)
        self.assertIsNone(result.score)

    def test_trusted_test_certificate_records_verified_connection(self):
        # Trust is changed only for this client context, never in system settings.
        trusted = ssl.create_default_context(cafile=str(self.fixtures / "localhost-cert.pem"))
        with patch("rudy_web_audit.transport.ssl.create_default_context", return_value=trusted):
            result = scan(self.url, allow_private=True)
        self.assertIsNone(result.error)
        self.assertTrue(result.hops[0].tls["verified"])
        self.assertEqual(len(result.hops[0].tls["sha256"]), 64)
        self.assertEqual(result.score, 100)

    def test_hostname_verification_remains_enabled(self):
        trusted = ssl.create_default_context(cafile=str(self.fixtures / "localhost-cert.pem"))
        addresses = socket.getaddrinfo("127.0.0.1", self.server.server_port, type=socket.SOCK_STREAM)
        with patch("rudy_web_audit.transport.ssl.create_default_context", return_value=trusted), \
                patch("rudy_web_audit.transport.resolve", return_value=addresses):
            result = scan(f"https://wrong-host.example:{self.server.server_port}/", allow_private=True)
        self.assertIn("certificate verification failed", result.error)


if __name__ == "__main__":
    unittest.main()
