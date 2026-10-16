import base64
import hashlib
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import __version__


def document(audits) -> dict:
    return {"schema_version": 1, "tool": "Rudy Web Audit", "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(), "targets": [audit.to_dict() for audit in audits]}


def load_document(path: str) -> dict:
    if Path(path).stat().st_size > 20_000_000:
        raise ValueError("Baseline exceeds the 20 MB limit.")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("targets"), list):
        raise ValueError("Baseline is not a supported Rudy Web Audit JSON report.")
    for target in data["targets"]:
        if not isinstance(target, dict) or not isinstance(target.get("target_id"), str) or not isinstance(target.get("target"), str) or not isinstance(target.get("checks"), list):
            raise ValueError("Baseline contains an invalid target.")
        for check in target["checks"]:
            if not isinstance(check, dict) or not all(isinstance(check.get(key), str) for key in ("id", "status", "severity", "evidence")):
                raise ValueError("Baseline contains an invalid check.")
            if check["status"] not in {"pass", "info", "warn", "fail"} or check["severity"] not in {"info", "low", "medium", "high", "critical"}:
                raise ValueError("Baseline contains an unsupported check status or severity.")
    return data


def _key(check):
    # Cookie rules need a stable cookie name; other rules compare by rule + hop.
    evidence = check["evidence"].split(":", 1)[0] if check["id"].startswith("COOKIE.") else ""
    return check["id"], check.get("hop"), evidence


def _rank(check):
    status = {"pass": 0, "info": 0, "warn": 1, "fail": 2}.get(check["status"], 0)
    severity = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(check["severity"], 0)
    return status, severity if status else 0


def _group(checks):
    grouped = {}
    for check in checks:
        key = _key(check)
        if key not in grouped or _rank(check) > _rank(grouped[key]):
            grouped[key] = check
    return grouped


def compare(before: dict, after: dict) -> dict:
    previous = {target["target_id"]: target for target in before["targets"]}
    current_ids = {target["target_id"] for target in after["targets"]}
    diff = {"regressions": [], "improvements": [], "new_targets": [], "removed_targets": [], "incomparable": []}
    for target in after["targets"]:
        old = previous.get(target["target_id"])
        if not old:
            diff["new_targets"].append(target["target"])
            continue
        if old.get("error") or target.get("error"):
            diff["incomparable"].append({"target": target["target"], "before_error": old.get("error"), "after_error": target.get("error")})
            continue
        older, newer = _group(old["checks"]), _group(target["checks"])
        for key in older.keys() | newer.keys():
            left, right = older.get(key), newer.get(key)
            left_rank = _rank(left) if left else (0, 0)
            right_rank = _rank(right) if right else (0, 0)
            if left_rank == right_rank:
                continue
            item = {"target": target["target"], "rule": key[0], "hop": key[1],
                    "before": left["status"] if left else "absent", "after": right["status"] if right else "absent"}
            diff["regressions" if right_rank > left_rank else "improvements"].append(item)
    diff["removed_targets"] = [target["target"] for target in before["targets"] if target["target_id"] not in current_ids]
    for key in ("regressions", "improvements"):
        diff[key].sort(key=lambda item: (item["target"], item["rule"], item["hop"] or 0))
    return diff


def sarif(data: dict) -> dict:
    checks = [(target, check) for target in data["targets"] for check in target["checks"] if check["status"] in {"fail", "warn"}]
    rules = {check["id"]: {"id": check["id"], "shortDescription": {"text": check["title"]},
                           "help": {"text": check["recommendation"]}} for _, check in checks}
    results = []
    for target, check in checks:
        identity = "|".join(map(str, (target["target_id"], *_key(check))))
        results.append({"ruleId": check["id"], "level": "error" if check["status"] == "fail" else "warning",
                        "message": {"text": f"{target['target']} — {check['evidence']}. {check['recommendation']}"},
                        "partialFingerprints": {"rudyFinding/v1": hashlib.sha256(identity.encode()).hexdigest()},
                        "properties": {"target": target["target"], "severity": check["severity"], "hop": check["hop"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Rudy Web Audit", "version": __version__,
                                           "informationUri": "https://github.com/r4venrudy/rudy-web-audit",
                                           "rules": list(rules.values())}},
                      "invocations": [{"executionSuccessful": not any(target["error"] for target in data["targets"])}],
                      "results": results}]}


def text_report(data: dict) -> str:
    lines = [f"RUDY WEB AUDIT {__version__}", "Hardening observations, not a vulnerability certification.", ""]
    for target in data["targets"]:
        lines.append(f"{target['grade']:7} {str(target['score']) if target['score'] is not None else 'n/a':>3}  {target['target']}")
        for index, hop in enumerate(target["hops"]):
            lines.append(f"  hop {index}: HTTP {hop['status']}  {hop['url']}  [{hop['ip']}]  {hop['elapsed_ms']} ms")
        if target["error"]:
            lines.append("  ERROR " + target["error"])
        # failures before warnings, then by severity, so the top lines are the ones to fix first
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        issues = sorted((check for check in target["checks"] if check["status"] in {"warn", "fail"}),
                        key=lambda check: (check["status"] != "fail", order.get(check["severity"], 5)))
        for check in issues:
            lines.append(f"  {check['status'].upper():4} [{check['severity']}] {check['id']}: {check['evidence']}")
        lines.append("")
    if "comparison" in data:
        diff = data["comparison"]
        lines.append(f"Baseline: {len(diff['regressions'])} regressions, {len(diff['improvements'])} improvements, {len(diff['incomparable'])} incomparable targets.")
        # the counts alone send people to the JSON to find out what changed
        for item in diff["regressions"]:
            hop = f" (hop {item['hop']})" if item["hop"] is not None else ""
            lines.append(f"  REGRESSION {item['target']} {item['rule']}{hop}: {item['before']} -> {item['after']}")
        for name in diff["new_targets"]:
            lines.append(f"  NEW TARGET {name}")
        for name in diff["removed_targets"]:
            lines.append(f"  REMOVED    {name}")
    # Never let untrusted header/cookie names write terminal control sequences.
    return "\n".join(lines).translate({code: None for code in range(32) if code not in (9, 10)})


def html_report(data: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    cards = []
    for target in data["targets"]:
        rows = []
        for check in target["checks"]:
            rows.append(f'<tr data-status="{esc(check["status"])}"><td><span class="pill {esc(check["status"])}">{esc(check["status"])}</span></td>'
                        f'<td><strong>{esc(check["title"])}</strong><small>{esc(check["id"])} · {esc(check["severity"])} · hop {esc(check["hop"])}</small></td>'
                        f'<td>{esc(check["evidence"])}</td><td>{esc(check["recommendation"])}</td></tr>')
        hops = "".join(f'<li><span class="code">{esc(hop["status"])}</span> {esc(hop["url"])}<small>{esc(hop["ip"])} · {esc(hop["elapsed_ms"])} ms'
                       + (f' · {esc(hop["tls"]["version"])} · expires {esc(hop["tls"]["expires_at"])}' if hop["tls"] else '') + '</small></li>' for hop in target["hops"])
        error = f'<p class="error">{esc(target["error"])}</p>' if target["error"] else ''
        cards.append(f'<article><div class="target"><div><p class="eyebrow">TARGET OBSERVATION</p><h2>{esc(target["target"])}</h2></div>'
                     f'<div class="score">{esc(target["grade"])}<small>{esc(target["score"] if target["score"] is not None else "—")} / 100</small></div></div>{error}'
                     f'<ol class="hops">{hops}</ol><div class="table-wrap"><table><thead><tr><th>State</th><th>Check</th><th>Evidence</th><th>Next step</th></tr></thead>'
                     f'<tbody>{"".join(rows)}</tbody></table></div></article>')
    comparison = ''
    if "comparison" in data:
        diff = data["comparison"]
        changes = "".join(f'<li>{esc(item["target"])} · {esc(item["rule"])} · {esc(item["before"])} → {esc(item["after"])}</li>' for item in diff["regressions"])
        comparison = f'<aside><h2>Baseline comparison</h2><p>{len(diff["regressions"])} regressions · {len(diff["improvements"])} improvements · {len(diff["incomparable"])} incomparable</p><ul>{changes}</ul></aside>'
    total = len(data["targets"])
    issues = sum(check["status"] in {"warn", "fail"} for target in data["targets"] for check in target["checks"])
    template = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-__SCRIPT_HASH__'; base-uri 'none'; form-action 'none'">
<title>Rudy Web Audit — evidence report</title><style>
:root{color-scheme:dark;--bg:#0a1018;--panel:#101b28;--line:#243448;--muted:#97acc1;--accent:#55e0b6}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#edf4fc;font:15px/1.6 system-ui,sans-serif}main{max-width:1400px;margin:auto;padding:60px 28px}header{border-bottom:1px solid var(--line);padding-bottom:32px;margin-bottom:28px}.eyebrow{letter-spacing:.18em;font-size:11px;font-weight:750;color:var(--accent)}h1{font-size:clamp(36px,6vw,64px);letter-spacing:-.045em;line-height:1.1;margin:14px 0}h2{font-size:20px;overflow-wrap:anywhere;margin:0}p{color:var(--muted)}.stats{display:flex;gap:28px;margin-top:28px}.stats strong{font-size:27px;color:white}small{display:block;color:var(--muted);font-size:12px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:26px 0}button{background:var(--panel);color:#edf4fc;border:1px solid var(--line);padding:9px 18px;border-radius:6px;cursor:pointer}button[aria-pressed=true]{border-color:var(--accent);color:var(--accent)}article,aside{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:26px;margin:22px 0}.target{display:flex;gap:20px;justify-content:space-between;align-items:center}.score{font-size:42px;color:var(--accent);min-width:95px;text-align:right}.score small{font-size:11px}.hops{border-left:2px solid var(--line);list-style:none;padding:0 0 0 22px;margin:26px 0}.hops li{margin:12px 0;overflow-wrap:anywhere}.code{font-family:monospace;color:var(--accent);padding-right:10px}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;color:var(--muted);font-size:11px;letter-spacing:.1em;text-transform:uppercase}td,th{border-bottom:1px solid var(--line);padding:15px 12px;vertical-align:top}td{min-width:150px;overflow-wrap:anywhere}.pill{padding:3px 8px;border:1px solid currentColor;border-radius:4px;font-size:10px;text-transform:uppercase}.pass{color:var(--accent)}.warn{color:#ffd279}.fail,.error{color:#ff9b99}.info{color:#9bbef4}footer{margin-top:40px;color:var(--muted);font-size:12px}[hidden]{display:none!important}@media(max-width:600px){main{padding:32px 14px}article{padding:18px}.target{align-items:flex-start}.score{font-size:30px;min-width:70px}}
</style></head><body><main><header><p class="eyebrow">R4VENRUDY / SECURITY RESEARCH</p><h1>Observe. Explain.<br>Track the change.</h1><p>Rudy Web Audit __VERSION__ · HTTP &amp; TLS evidence report</p><div class="stats"><div><strong>__TOTAL__</strong><small>targets</small></div><div><strong>__ISSUES__</strong><small>observations to review</small></div></div></header>
<nav class="toolbar" aria-label="Filter checks"><button data-filter="all" aria-pressed="true">All checks</button><button data-filter="issues" aria-pressed="false">Needs review</button><button data-filter="pass" aria-pressed="false">Passed</button></nav>__COMPARISON____CARDS__
<footer>Generated __TIME__. A heuristic hardening score is not a vulnerability certification. Checks reflect these responses, paths, and TLS handshakes only. No page scripts executed. No cookie values exported.</footer></main><script>__SCRIPT__</script></body></html>'''
    script = "document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-filter]').forEach(x=>x.setAttribute('aria-pressed',String(x===b)));document.querySelectorAll('tr[data-status]').forEach(r=>{r.hidden=b.dataset.filter==='issues'?!['warn','fail'].includes(r.dataset.status):b.dataset.filter==='pass'?r.dataset.status!=='pass':false})}));"
    replacements = {"__VERSION__": esc(__version__), "__TOTAL__": str(total), "__ISSUES__": str(issues),
                    "__COMPARISON__": comparison, "__CARDS__": "".join(cards), "__TIME__": esc(data["generated_at"]),
                    "__SCRIPT_HASH__": base64.b64encode(hashlib.sha256(script.encode()).digest()).decode(), "__SCRIPT__": script}
    # Replace template tokens in a single pass so untrusted values cannot create new tokens.
    return re.sub("|".join(map(re.escape, replacements)), lambda match: replacements[match.group()], template)
