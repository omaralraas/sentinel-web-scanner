"""
Utility: reporter
===================
Serialises scan findings into a timestamped JSON report file
inside the ``reports/`` directory.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentinel.reporter")

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def save_json_report(
    target: str,
    findings: list[dict[str, Any]],
    duration: float,
    modules: list[str],
) -> Path:
    """Write all findings to a timestamped JSON file and return its path.

    Parameters
    ----------
    target : str
        The URL that was scanned.
    findings : list[dict]
        All findings collected from every module.
    duration : float
        Total scan time in seconds.
    modules : list[str]
        Names of modules that were executed.

    Returns
    -------
    Path
        Absolute path to the generated report file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_target = (
        target.replace("://", "_").replace("/", "_").replace(":", "_")
    )
    filename = f"scan_{safe_target}_{timestamp}.json"
    report_path = REPORTS_DIR / filename

    # ── Build severity summary ──────────────────────────────────────────
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report: dict[str, Any] = {
        "meta": {
            "tool":       "Sentinel Web Scanner v1.0",
            "target":     target,
            "scan_time":  timestamp,
            "duration_s": duration,
            "modules":    modules,
        },
        "summary": {
            "total_findings":  len(findings),
            "by_severity":     severity_counts,
        },
        "findings": findings,
    }

    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    logger.debug("Report written to %s", report_path)
    return report_path
