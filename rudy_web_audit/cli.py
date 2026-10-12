import argparse
import json
import math
import sys
from pathlib import Path

from . import __version__
from .report import compare, document, html_report, load_document, sarif, text_report
from .scanner import scan_many


def bounded_int(low, high):
    def parse(value):
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("Expected an integer.") from exc
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"Choose a number between {low} and {high}.")
        return number
    return parse


def timeout_value(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected a timeout in seconds.") from exc
    if not math.isfinite(number) or not 0.1 <= number <= 60:
        raise argparse.ArgumentTypeError("Timeout must be between 0.1 and 60 seconds.")
    return number


def parser():
    result = argparse.ArgumentParser(description="HTTP/TLS hardening evidence, offline reports and regression detection.")
    result.add_argument("targets", nargs="*", help="URL or hostname; HTTPS is the default.")
    result.add_argument("--targets-file", help="UTF-8 text file, one target per line. # comments supported.")
    result.add_argument("--workers", type=bounded_int(1, 16), default=4)
    result.add_argument("--timeout", type=timeout_value, default=10, help="Socket-operation timeout in seconds (default: 10).")
    result.add_argument("--max-redirects", type=bounded_int(0, 10), default=5)
    result.add_argument("--allow-private", action="store_true", help="Allow destinations on your own private/local network.")
    result.add_argument("--format", choices=("text", "json", "html", "sarif", "evidence"), default="text")
    result.add_argument("--evidence-scope", help="Stable project/site namespace; required for evidence output.")
    result.add_argument("--evidence-library", help="Absolute trusted Rudy Evidence shared-library path (or RUDY_EVIDENCE_LIBRARY).")
    result.add_argument("--output", "-o", help="Write the report to this file.")
    result.add_argument("--baseline", help="Compare with an earlier JSON report.")
    result.add_argument("--fail-on", choices=("low", "medium", "high", "critical", "regression"), help="Return exit code 1 for matching findings.")
    result.add_argument("--version", action="version", version=__version__)
    return result


def main(argv=None):
    arg_parser = parser()
    args = arg_parser.parse_args(argv)
    try:
        evidence = None
        if args.format == "evidence":
            if not args.evidence_scope or not args.evidence_scope.strip():
                raise ValueError("--format evidence requires a stable --evidence-scope.")
            if args.baseline:
                raise ValueError("Evidence output does not include legacy baseline comparisons; export JSON or compare evidence bundles separately.")
            try:
                from rudy_evidence import Evidence
            except ImportError as exc:
                raise ValueError("Install the optional Rudy Evidence Python binding; see the README.") from exc
            evidence = Evidence(args.evidence_library)
        elif args.evidence_scope or args.evidence_library:
            raise ValueError("Evidence options require --format evidence.")
        targets = list(args.targets)
        if args.targets_file:
            path = Path(args.targets_file)
            if path.stat().st_size > 1_000_000:
                raise ValueError("Target file exceeds the 1 MB limit.")
            targets += [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines()
                        if line.strip() and not line.lstrip().startswith("#")]
        targets = list(dict.fromkeys(targets))
        if not targets or len(targets) > 200:
            raise ValueError("Supply between 1 and 200 unique targets.")
        if args.fail_on == "regression" and not args.baseline:
            raise ValueError("--fail-on regression requires --baseline.")
        baseline = load_document(args.baseline) if args.baseline else None
        audits = scan_many(targets, workers=args.workers, timeout=args.timeout,
                           max_redirects=args.max_redirects, allow_private=args.allow_private)
        data = document(audits)
        if baseline:
            data["comparison"] = compare(baseline, data)
        rendered = (json.dumps(evidence.normalize("rudy-web-audit", args.evidence_scope, data), indent=2, ensure_ascii=True) if evidence else
                    json.dumps(data, indent=2, ensure_ascii=True) if args.format == "json" else
                    json.dumps(sarif(data), indent=2, ensure_ascii=True) if args.format == "sarif" else
                    html_report(data) if args.format == "html" else text_report(data))
        if args.output:
            path = Path(args.output)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered + "\n", encoding="utf-8")
            print(f"Report saved: {path}", file=sys.stderr)
        else:
            try:
                sys.stdout.write(rendered + "\n")
            except UnicodeEncodeError:
                sys.stdout.buffer.write((rendered + "\n").encode("utf-8"))
        # An incomplete scan is never a successful gate, regardless of findings.
        if any(audit.error for audit in audits):
            return 2
        if args.fail_on == "regression":
            diff = data["comparison"]
            if diff["incomparable"] or diff["new_targets"] or diff["removed_targets"]:
                return 2
            return int(bool(diff["regressions"]))
        if args.fail_on:
            ranks = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            return int(any(check.status in {"fail", "warn"} and ranks[check.severity] >= ranks[args.fail_on]
                           for audit in audits for check in audit.checks))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
