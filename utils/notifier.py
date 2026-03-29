"""
Utility: notifier
===================
Sends a formatted embed to a Discord Webhook containing
all High / Critical findings from a scan.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger("sentinel.notifier")

# Discord embed colour (red for alerts)
EMBED_COLOR = 0xFF4444


def _build_embed(target: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Construct a Discord embed payload from a list of findings."""
    fields: list[dict[str, str | bool]] = []

    for f in findings[:25]:  # Discord allows max 25 fields per embed
        value = f.get("detail", "No detail provided.")
        if f.get("evidence"):
            value += f"\n```\n{f['evidence']}\n```"
        fields.append({
            "name":   f"⚠ [{f.get('severity', '?')}] {f.get('title', 'Untitled')}",
            "value":  value[:1024],  # Discord field value limit
            "inline": False,
        })

    embed: dict[str, Any] = {
        "title":       "🛡️ Sentinel Scan Alert",
        "description": (
            f"**Target:** `{target}`\n"
            f"**High/Critical Findings:** {len(findings)}"
        ),
        "color":  EMBED_COLOR,
        "fields": fields,
        "footer": {"text": "Sentinel Web Scanner v1.0"},
    }
    return embed


def send_discord_alert(
    webhook_url: str,
    target: str,
    findings: list[dict[str, Any]],
) -> bool:
    """Post an alert embed to the given Discord webhook.

    Parameters
    ----------
    webhook_url : str
        Full Discord Webhook URL.
    target : str
        The URL that was scanned.
    findings : list[dict]
        Findings to include (should already be filtered to High/Critical).

    Returns
    -------
    bool
        True if the message was sent successfully; False otherwise.
    """
    if not webhook_url:
        logger.debug("No Discord webhook configured — skipping alert.")
        return False

    payload: dict[str, Any] = {
        "username":   "Sentinel Scanner",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/6357/6357048.png",
        "embeds":     [_build_embed(target, findings)],
    }

    try:
        resp = requests.post(
            webhook_url,
            json=payload,
            timeout=10,
        )
        if resp.status_code in (200, 204):
            logger.info("Discord alert sent successfully. ✉️")
            return True
        else:
            logger.warning(
                "Discord webhook returned HTTP %d: %s",
                resp.status_code, resp.text[:200],
            )
            return False
    except requests.RequestException as exc:
        logger.error("Failed to send Discord alert: %s", exc)
        return False
