"""Capability catalog and proof-readiness guardrails."""
from __future__ import annotations

from pathlib import Path
from .common import envelope


MODULES = (
    ("verify", "ready", "Package, provenance and observed-worker evidence"),
    ("hunt", "ready", "Offline access/error/EDR triage"),
    ("repo-audit", "ready", "Dockerfile and Compose PHP image review"),
    ("config-audit", "ready", "PHP configuration heuristics"),
    ("webcheck", "ready", "Authorized single HEAD metadata check"),
    ("rules", "ready", "Review-only WAF and Sigma templates"),
    ("differential-proof", "not-implemented", "Pinned vulnerable/patched lab with an identical bounded regression input"),
)


def one_status(root: Path | None = None) -> dict:
    base = root or Path.cwd()
    findings = []
    for name, status, description in MODULES:
        findings.append({
            "severity": "info" if status == "ready" else "medium",
            "rule_id": "MODULE_" + status.replace("-", "_").upper(),
            "source": str(base),
            "message": f"{name}: {status} — {description}",
            "evidence": "No exploit traffic is generated",
        })
    return envelope("one", findings, notes=[
        "The defensive modules are operational.",
        "Differential proof remains NOT IMPLEMENTED until pinned vulnerable and patched builds, an identical bounded input, and a negative control are present.",
        "Do not describe inventory, version comparison or a patched-only smoke test as a PHP2Shell PoC.",
    ])
