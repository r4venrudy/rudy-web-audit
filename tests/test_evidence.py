import io
import json
import os
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch
from rudy_web_audit.cli import main
from rudy_web_audit.models import Audit, Check

class EvidenceOptions(unittest.TestCase):
    def test_scope_required_before_scanning(self):
        with patch("rudy_web_audit.cli.scan_many") as scan, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["example.test", "--format", "evidence"]), 2)
            scan.assert_not_called()

    def test_baseline_rejected_before_scanning(self):
        with patch("rudy_web_audit.cli.scan_many") as scan, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["example.test", "--format", "evidence", "--evidence-scope", "site:one", "--baseline", "prior.json"]), 2)
            scan.assert_not_called()

@unittest.skipUnless(os.environ.get("RUDY_EVIDENCE_LIBRARY"), "Native SDK integration requires RUDY_EVIDENCE_LIBRARY")
class NativeEvidence(unittest.TestCase):
    def test_actual_native_export_and_gate(self):
        audit = Audit("https://example.test/", "fixture-one")
        audit.checks = [Check("TEST.FAIL", "Review setting", "warn", "high", "token=synthetic_secret", "Review"),
                        Check("TEST.PASS", "Passing", "pass", "info", "OK", "None")]
        out = io.StringIO()
        with patch("rudy_web_audit.cli.scan_many", return_value=[audit]), redirect_stdout(out):
            code = main(["example.test", "--format", "evidence", "--evidence-scope", "site:one", "--fail-on", "high"])
        doc = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(doc["schema"], "rudy-evidence/v1")
        self.assertEqual(len(doc["findings"]), 1)
        self.assertEqual(doc["findings"][0]["scope"], "site:one")
        self.assertNotIn("synthetic_secret", out.getvalue())
        from rudy_evidence import Evidence
        self.assertTrue(Evidence().process(dict(operation="validate", document=doc))["valid"])

    def test_scan_errors_still_return_incomplete_exit(self):
        audit = Audit("https://example.test/", "fixture-one"); audit.error = "Synthetic failure"
        with patch("rudy_web_audit.cli.scan_many", return_value=[audit]), redirect_stdout(io.StringIO()):
            self.assertEqual(main(["example.test", "--format", "evidence", "--evidence-scope", "site:one"]), 2)
