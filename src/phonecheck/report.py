"""Render a Report as plain text (terminal), HTML (to show a customer) or JSON (for other programs).

Everything printed from a phone is untrusted text (a version string is whatever
the app's author typed), so the HTML renderer escapes every dynamic value.
"""

from __future__ import annotations

import html
import json
import textwrap
from typing import Any

from . import __version__
from .models import Finding, Level, Report

DISCLAIMER = (
    "These are signals, not verdicts. Review each app with the phone's owner before removing anything."
)
USB_REMINDER = "When you are finished, turn USB debugging off again (Settings > Developer options)."
NOTHING_FOUND = (
    "Nothing suspicious found among the installed apps. That is not proof the phone is clean: "
    "this check only sees the app details Android will share over USB."
)


def _installed(finding: Finding) -> str | None:
    when = finding.app.first_install
    return when.strftime("%Y-%m-%d") if when else None


def _source(finding: Finding) -> str:
    return finding.app.installer or "unknown (a file or a computer)"


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def to_dict(report: Report) -> dict[str, Any]:
    d = report.device
    return {
        "tool": "phonecheck",
        "version": __version__,
        "device": {
            "manufacturer": d.manufacturer,
            "model": d.model,
            "android": d.android_release,
            "battery_level": d.battery_level,
            "storage_used_pct": d.storage_used_pct,
            "storage_free_gb": round(d.storage_free_gb, 1) if d.storage_free_gb is not None else None,
            "scanned_at": d.taken_at.isoformat() if d.taken_at else None,
        },
        "scanned_apps": report.scanned,
        "findings": [
            {
                "package": f.app.package,
                "level": f.level.value,
                "score": f.score,
                "version": f.app.version_name,
                "installed": _installed(f),
                "installer": f.app.installer,
                "signals": [{"rule": s.rule, "points": s.points, "reason": s.reason} for s in f.signals],
                "removal_note": f.removal_note,
            }
            for f in report.findings
        ],
        "device_notes": list(report.device_notes),
    }


def render_json(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2) + "\n"


# --------------------------------------------------------------------------
# Plain text
# --------------------------------------------------------------------------


def format_finding(finding: Finding, number: int, width: int = 78) -> list[str]:
    lines = [f"{number:>2}. {finding.app.package}   (score {finding.score})"]
    details = []
    if finding.app.version_name:
        details.append(f"version {finding.app.version_name}")
    if _installed(finding):
        details.append(f"installed {_installed(finding)}")
    details.append(f"from: {_source(finding)}")
    lines.append("    " + "  |  ".join(details))
    for signal in finding.signals:
        lines.extend(
            textwrap.wrap(signal.reason, width=width, initial_indent="    - ", subsequent_indent="      ", break_on_hyphens=False)
        )
    if finding.removal_note:
        lines.extend(textwrap.wrap(f"Note: {finding.removal_note}", width=width, initial_indent="    ", subsequent_indent="    "))
    return lines


def render_text(report: Report) -> str:
    d = report.device
    lines = [f"Phone checkup: {d.display_name} (Android {d.android_release})"]
    facts = []
    if d.battery_level is not None:
        facts.append(f"battery {d.battery_level}%")
    if d.storage_used_pct is not None:
        facts.append(f"storage {d.storage_used_pct}% full")
    if facts:
        lines.append(", ".join(facts))
    lines.append(f"Checked {report.scanned} user-installed apps. System apps are not checked.")
    lines.append("")

    if not report.findings:
        lines.extend(textwrap.wrap(NOTHING_FOUND, width=78))
        lines.append("")

    number = 0
    for title, level in (("LIKELY JUNK", Level.HIGH), ("WORTH A LOOK", Level.MEDIUM)):
        group = [f for f in report.findings if f.level is level]
        if not group:
            continue
        lines.append(f"{title} ({len(group)})")
        for finding in group:
            number += 1
            lines.extend(format_finding(finding, number))
            lines.append("")

    if report.device_notes:
        lines.append("ABOUT THE PHONE")
        for note in report.device_notes:
            lines.extend(textwrap.wrap(note, width=78, initial_indent="  - ", subsequent_indent="    "))
        lines.append("")

    lines.extend(textwrap.wrap(DISCLAIMER, width=78))
    lines.extend(textwrap.wrap(USB_REMINDER, width=78))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# HTML (one self-contained page: no scripts, no external requests)
# --------------------------------------------------------------------------

_CSS = """
:root{--bg:#fff;--fg:#1d1d1f;--muted:#5f6368;--line:#e2e2e6;--card:#fafafa;
--high:#b3261e;--high-bg:#fdecea;--med:#8a5a00;--med-bg:#fff4d6;--ok:#1b6e3c;--ok-bg:#e6f4ea}
@media (prefers-color-scheme:dark){:root{--bg:#121214;--fg:#f2f2f4;--muted:#a5a8ad;--line:#2f2f35;--card:#1b1b1f;
--high:#ffb4ab;--high-bg:#4a1b17;--med:#ffd479;--med-bg:#43330a;--ok:#9be3b1;--ok-bg:#13361f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:18px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:760px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 8px}
.sub{color:var(--muted);margin:0 0 20px}
.banner{border-radius:12px;padding:16px 18px;font-weight:600;margin-bottom:8px}
.banner.high{background:var(--high-bg);color:var(--high)}.banner.med{background:var(--med-bg);color:var(--med)}
.banner.ok{background:var(--ok-bg);color:var(--ok)}
.card{border:1px solid var(--line);background:var(--card);border-radius:12px;padding:14px 16px;margin:10px 0}
.card h3{margin:0;font-size:1rem;word-break:break-all}
.tag{display:inline-block;border-radius:999px;padding:1px 10px;font-size:.8rem;font-weight:700;margin-right:8px}
.tag.high{background:var(--high-bg);color:var(--high)}.tag.med{background:var(--med-bg);color:var(--med)}
.meta{color:var(--muted);font-size:.85rem;margin:2px 0 8px}
ul{margin:6px 0 0;padding-left:20px}li{margin:3px 0}
.note{margin-top:8px;font-size:.9rem;color:var(--muted)}
footer{margin-top:32px;color:var(--muted);font-size:.85rem}
@media print{body{font-size:12pt}.card{break-inside:avoid}}
"""


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _card(finding: Finding) -> str:
    css = "high" if finding.level is Level.HIGH else "med"
    label = "Likely junk" if finding.level is Level.HIGH else "Worth a look"
    meta = []
    if finding.app.version_name:
        meta.append(f"version {_e(finding.app.version_name)}")
    if _installed(finding):
        meta.append(f"installed {_e(_installed(finding))}")
    meta.append(f"from {_e(_source(finding))}")
    reasons = "".join(f"<li>{_e(s.reason)}</li>" for s in finding.signals)
    note = f'<p class="note">{_e(finding.removal_note)}</p>' if finding.removal_note else ""
    return (
        f'<section class="card"><h3><span class="tag {css}">{label}</span>{_e(finding.app.package)}</h3>'
        f'<p class="meta">{" &middot; ".join(meta)}</p><ul>{reasons}</ul>{note}</section>'
    )


def render_html(report: Report) -> str:
    d = report.device
    high = [f for f in report.findings if f.level is Level.HIGH]
    medium = [f for f in report.findings if f.level is Level.MEDIUM]
    if high:
        banner = ("high", f"{len(high)} app{'s' if len(high) != 1 else ''} very likely to be junk")
    elif medium:
        banner = ("med", f"{len(medium)} app{'s' if len(medium) != 1 else ''} worth a closer look")
    else:
        banner = ("ok", "Nothing suspicious found")

    facts = []
    if d.battery_level is not None:
        facts.append(f"Battery {d.battery_level}%")
    if d.storage_used_pct is not None:
        facts.append(f"Storage {d.storage_used_pct}% full")
    facts.append(f"{report.scanned} apps checked")

    body = [
        "<h1>Phone checkup</h1>",
        f'<p class="sub">{_e(d.display_name)} &middot; Android {_e(d.android_release)} &middot; {_e(" · ".join(facts))}</p>',
        f'<div class="banner {banner[0]}">{_e(banner[1])}</div>',
    ]
    if not report.findings:
        body.append(f"<p>{_e(NOTHING_FOUND)}</p>")
    if high:
        body.append("<h2>Likely junk</h2>" + "".join(_card(f) for f in high))
    if medium:
        body.append("<h2>Worth a look</h2>" + "".join(_card(f) for f in medium))
    if report.device_notes:
        items = "".join(f"<li>{_e(n)}</li>" for n in report.device_notes)
        body.append(f"<h2>About the phone</h2><ul>{items}</ul>")
    body.append(f"<footer>{_e(DISCLAIMER)} {_e(USB_REMINDER)} Generated by phonecheck {_e(__version__)}.</footer>")

    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Phone checkup</title>"
        f"<style>{_CSS}</style></head><body><main>{''.join(body)}</main></body></html>\n"
    )
