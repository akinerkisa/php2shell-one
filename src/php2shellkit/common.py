"""Common report utilities. Never infer vulnerability status from absence of evidence."""
from __future__ import annotations

import csv
import io
import html
import json
from datetime import datetime, timezone
from pathlib import Path

CVES = ("CVE-2026-109618", "CVE-2026-109619")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def envelope(command: str, findings: list[dict], *, notes: list[str] | None = None) -> dict:
    return {
        "schema_version": "1", "tool": "php2shell-one", "command": command,
        "generated_at": utc_now(), "cves": list(CVES), "findings": findings,
        "limitations": notes or [],
        "summary": {
            "total": len(findings),
            "high": sum(f.get("severity") == "high" for f in findings),
            "medium": sum(f.get("severity") == "medium" for f in findings),
            "low": sum(f.get("severity") == "low" for f in findings),
            "info": sum(f.get("severity") == "info" for f in findings),
        },
    }


def format_report(report: dict, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False)
    if fmt == "csv":
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=["severity", "rule_id", "source", "line", "message", "evidence"])
        writer.writeheader()
        for finding in report.get("findings", []):
            writer.writerow({k: str(finding.get(k, "")) for k in writer.fieldnames})
        return out.getvalue().rstrip("\n")
    if fmt == "html":
        rows = []
        for f in report.get("findings", []):
            fields = [f.get("severity", "info"), f.get("rule_id", ""), f.get("source", ""),
                      str(f.get("line", "")), f.get("message", ""), f.get("evidence", "")]
            rows.append("<tr>" + "".join("<td>" + html.escape(str(v), quote=True) + "</td>" for v in fields) + "</tr>")
        notes = "".join("<li>" + html.escape(str(n), quote=True) + "</li>" for n in report.get("limitations", []))
        name = html.escape(str(report.get("command", "report")), quote=True)
        return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                "<title>PHP2Shell One - " + name + "</title>"
                "<style>body{font:15px system-ui;margin:2rem auto;max-width:1150px;padding:0 1rem;color:#202936}"
                "h1{font-size:1.7rem}table{border-collapse:collapse;width:100%}"
                "th,td{border:1px solid #dae0e7;text-align:left;padding:.6rem;overflow-wrap:anywhere}"
                "th{background:#f2f4f7}tr:nth-child(even){background:#fafbfc}"
                ".muted{color:#56616e}li{margin:.3rem 0}</style></head><body>"
                "<h1>PHP2Shell One</h1><p class=\"muted\">" + name + " — offline generated report</p>"
                "<table><thead><tr><th>Severity</th><th>Rule</th><th>Source</th><th>Line</th><th>Observation</th><th>Evidence</th></tr>"
                "</thead><tbody>" + "".join(rows) + "</tbody></table><h2>Limitations</h2><ul>" + notes +
                "</ul><p>Findings are triage signals, not proof of compromise or complete mitigation.</p></body></html>")
    if fmt == "sarif":
        rules = sorted({f.get("rule_id", "OBSERVATION") for f in report.get("findings", [])})
        data = {
            "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "PHP2Shell One", "rules": [
                {"id": r, "shortDescription": {"text": r}} for r in rules]}},
                "results": [{
                    "ruleId": f.get("rule_id", "OBSERVATION"),
                    "level": {"high": "error", "medium": "warning", "low": "note", "info": "note"}.get(f.get("severity"), "note"),
                    "message": {"text": f.get("message", "")},
                    **({"locations": [{"physicalLocation": {"artifactLocation": {"uri": f["source"]},
                        "region": {"startLine": max(1, int(f["line"]))}}}]} if f.get("source") and f.get("line") else {})
                } for f in report.get("findings", [])]
            }]
        }
        return json.dumps(data, indent=2)
    lines = ["PHP2Shell One | " + report.get("command", "report")]
    if "summary" in report:
        s = report["summary"]
        lines.append(f"Findings: {s['total']} (high {s['high']}, medium {s['medium']}, low {s['low']}, info {s['info']})")
    for f in report.get("findings", []):
        place = f.get("source", "") + (f":{f['line']}" if f.get("line") else "")
        lines.append(f"[{f.get('severity', 'info').upper()}] {f.get('rule_id', '')} {place} — {f.get('message', '')}")
        if f.get("evidence"):
            lines.append("  evidence: " + str(f["evidence"])[:180])
    for note in report.get("limitations", []):
        lines.append("NOTE: " + note)
    return "\n".join(lines)


def write_report(report: dict, fmt: str, destination: Path | None) -> None:
    result = format_report(report, fmt)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(result + "\n", encoding="utf-8")
    else:
        print(result)
