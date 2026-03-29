"""
Module: header_analyzer
========================
Inspects HTTP response headers from the target URL and flags
missing or misconfigured security headers that defend against
common web attacks (clickjacking, XSS, MIME-sniffing, etc.).

Exposed interface:
    run(target: str, config: dict) -> list[dict]
"""

from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger("sentinel.header_analyzer")

# ── Security Headers to Check ──────────────────────────────────────────────
# Each entry: (header_name, severity_if_missing, why_it_matters)
REQUIRED_HEADERS: list[tuple[str, str, str]] = [
    (
        "Strict-Transport-Security",
        "High",
        "HSTS is missing. The site does not enforce HTTPS, making it "
        "vulnerable to SSL-stripping / downgrade attacks.",
    ),
    (
        "Content-Security-Policy",
        "High",
        "CSP is missing. Without a Content-Security-Policy, the application "
        "is more susceptible to Cross-Site Scripting (XSS) attacks.",
    ),
    (
        "X-Frame-Options",
        "Medium",
        "X-Frame-Options is missing. The page can be embedded in an iframe, "
        "potentially enabling clickjacking attacks.",
    ),
    (
        "X-Content-Type-Options",
        "Medium",
        "X-Content-Type-Options is missing. Browsers may MIME-sniff "
        "responses, which can lead to XSS via content-type confusion.",
    ),
    (
        "Referrer-Policy",
        "Low",
        "Referrer-Policy is missing. Sensitive URL parameters may leak "
        "to third-party sites via the Referer header.",
    ),
    (
        "Permissions-Policy",
        "Low",
        "Permissions-Policy (formerly Feature-Policy) is missing. Browser "
        "features like camera, microphone, and geolocation are not restricted.",
    ),
]

# Known server banners that leak version info
SERVER_LEAK_KEYWORDS: list[str] = [
    "Apache/", "nginx/", "Microsoft-IIS/", "LiteSpeed/",
    "OpenResty/", "Jetty/", "Tomcat/",
]


def _check_missing_headers(
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    """Return findings for every required header that is absent."""
    findings: list[dict[str, Any]] = []

    for header_name, severity, detail in REQUIRED_HEADERS:
        value = headers.get(header_name)
        if value is None:
            findings.append({
                "module":   "header_analyzer",
                "severity": severity,
                "title":    f"Missing Header: {header_name}",
                "detail":   detail,
                "evidence": None,
            })
        else:
            logger.debug("✔ %s: %s", header_name, value)

    return findings


def _check_server_leak(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Flag the Server header if it leaks software version info."""
    findings: list[dict[str, Any]] = []
    server_value: str | None = headers.get("Server")

    if server_value is None:
        return findings

    for keyword in SERVER_LEAK_KEYWORDS:
        if keyword.lower() in server_value.lower():
            findings.append({
                "module":   "header_analyzer",
                "severity": "Medium",
                "title":    "Server Version Disclosure",
                "detail":   (
                    f"The Server header discloses software version "
                    f"information: '{server_value}'. This aids an attacker "
                    f"in fingerprinting the stack and targeting known CVEs."
                ),
                "evidence": f"Server: {server_value}",
            })
            break  # One finding is enough
    else:
        logger.debug("Server header present but no version leak detected: %s", server_value)

    return findings


# ── Public Interface ────────────────────────────────────────────────────────
def run(target: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    """Perform header analysis on *target* and return a list of findings.

    Parameters
    ----------
    target : str
        Fully qualified URL to scan (e.g. ``http://127.0.0.1:5000``).
    config : dict
        Parsed ``config.yaml`` contents.

    Returns
    -------
    list[dict]
        A list of finding dicts (may be empty if all headers are present).
    """
    timeout: int = config.get("scan_settings", {}).get("default_timeout", 5)
    user_agent: str = config.get("scan_settings", {}).get(
        "user_agent", "SentinelScanner/1.0"
    )

    logger.info("Sending GET request to %s …", target)

    try:
        response = requests.get(
            target,
            timeout=timeout,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
        )
    except requests.ConnectionError:
        logger.error("Connection refused — is the target running?")
        return [{
            "module":   "header_analyzer",
            "severity": "Info",
            "title":    "Connection Error",
            "detail":   f"Could not connect to {target}.",
            "evidence": None,
        }]
    except requests.Timeout:
        logger.error("Request timed out after %ds.", timeout)
        return [{
            "module":   "header_analyzer",
            "severity": "Info",
            "title":    "Request Timeout",
            "detail":   f"GET {target} timed out after {timeout}s.",
            "evidence": None,
        }]

    logger.info(
        "Received HTTP %d — analysing %d response headers …",
        response.status_code,
        len(response.headers),
    )

    # Case-insensitive header access (requests already does this)
    headers = dict(response.headers)

    findings: list[dict[str, Any]] = []
    findings.extend(_check_missing_headers(headers))
    findings.extend(_check_server_leak(headers))

    return findings
