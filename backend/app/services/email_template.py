"""Render the HTML alert email and a plaintext fallback."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TPL_DIR = Path(__file__).resolve().parent.parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TPL_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html", "j2", "html.j2")),
    trim_blocks=True,
    lstrip_blocks=True,
)

_SEVERITY_PALETTE = {
    "critical": ("#7f1d1d", "#fee2e2"),
    "high":     ("#9a3412", "#ffedd5"),
    "medium":   ("#854d0e", "#fef3c7"),
    "low":      ("#1e3a8a", "#dbeafe"),
    "none":     ("#1f2937", "#e5e7eb"),
}


def render_alert_email(payload: dict[str, Any]) -> tuple[str, str, str]:
    """Return (subject, html, text) tuple."""
    severity = (payload.get("severity") or "none").lower()
    bg, fg = _SEVERITY_PALETTE.get(severity, _SEVERITY_PALETTE["none"])

    ctx = {
        **payload,
        "severity": severity,
        "severity_bg": bg,
        "severity_fg": fg,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }

    tpl = _env.get_template("alert_email.html.j2")
    html = tpl.render(**ctx)

    cve_id = payload.get("cve_id", "CVE")
    subject = f"[VulnInt][{severity.upper()}] {cve_id} — {payload.get('title') or 'Vulnerability detected'}"

    # Plaintext fallback
    lines = [
        f"VulnInt Security Alert",
        f"=" * 50,
        f"CVE:        {cve_id}",
        f"Severity:   {severity.upper()}" + (f" (CVSS {payload.get('cvss'):.1f})" if payload.get("cvss") else ""),
        f"KEV:        {'YES' if payload.get('kev') else 'no'}",
        f"Exploit:    {'available' if payload.get('exploit_available') else 'unknown'}",
        "",
        payload.get("summary") or "",
        "",
    ]
    if payload.get("affected_servers"):
        lines.append("Affected servers:")
        for s in payload["affected_servers"]:
            lines.append(
                f"  - {s.get('hostname')} ({s.get('os_family')} {s.get('os_version','')})"
                f"  pkg={s.get('package')} installed={s.get('installed_version')}"
                f" fixed={s.get('fixed_version') or '-'}"
            )
        lines.append("")
    if payload.get("remediation"):
        lines += ["Remediation:", payload["remediation"], ""]
    if payload.get("references"):
        lines.append("References:")
        lines += [f"  - {r}" for r in payload["references"][:8]]
        lines.append("")
    lines.append(f"Dashboard: {payload.get('dashboard_url')}")
    text = "\n".join(lines)

    return subject, html, text
