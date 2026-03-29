"""
Module: api_fuzzer
===================
Discovers common API endpoints on the target and performs basic
IDOR (Insecure Direct Object Reference) testing by fuzzing integer
IDs and comparing responses.

Exposed interface:
    run(target: str, config: dict) -> list[dict]
"""

from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger("sentinel.api_fuzzer")

# ── Fallback wordlist (used when config has no api_paths) ───────────────────
DEFAULT_API_PATHS: list[str] = [
    "/api/v1/users",
    "/api/v1/admin",
    "/api/v1/config",
    "/api/v1/orders",
    "/api/v1/accounts",
    "/api/v2/users",
    "/graphql",
    "/api/health",
    "/api/status",
    "/api/docs",
    "/swagger.json",
    "/openapi.json",
]


def _normalise_target(target: str) -> str:
    """Strip trailing slash so we can safely append paths."""
    return target.rstrip("/")


def _discover_endpoints(
    target: str,
    paths: list[str],
    timeout: int,
    user_agent: str,
) -> list[dict[str, Any]]:
    """Probe each path and return metadata for the ones that respond.

    Returns a list of dicts with keys: path, status_code, content_length.
    """
    discovered: list[dict[str, Any]] = []

    for path in paths:
        url = f"{target}{path}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": user_agent},
                allow_redirects=False,
            )
        except (requests.ConnectionError, requests.Timeout):
            logger.debug("No response for %s", url)
            continue

        # Treat anything that isn't a 404/405/500 as "interesting"
        if resp.status_code not in (404, 405, 500, 502, 503):
            logger.info(
                "  [%d] %s  (%d bytes)",
                resp.status_code, path, len(resp.content),
            )
            discovered.append({
                "path": path,
                "status_code": resp.status_code,
                "content_length": len(resp.content),
            })
        else:
            logger.debug("  [%d] %s — skipped", resp.status_code, path)

    return discovered


def _test_idor(
    target: str,
    path: str,
    max_ids: int,
    timeout: int,
    user_agent: str,
) -> dict[str, Any] | None:
    """Fuzz integer IDs on an endpoint and detect potential IDOR.

    Strategy:
      1. Request ``path/1``, ``path/2``, … ``path/<max_ids>``.
      2. Collect the ones that return HTTP 200 with a non-trivial body.
      3. If ≥ 2 distinct bodies are returned → likely IDOR (unauthenticated
         access to different records).

    Returns a finding dict or None.
    """
    responses_200: list[dict[str, Any]] = []

    for i in range(1, max_ids + 1):
        url = f"{target}{path}/{i}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": user_agent},
                allow_redirects=False,
            )
        except (requests.ConnectionError, requests.Timeout):
            continue

        if resp.status_code == 200 and len(resp.content) > 2:
            responses_200.append({
                "id": i,
                "body": resp.text[:300],  # first 300 chars for evidence
                "length": len(resp.content),
            })

    if len(responses_200) < 2:
        return None

    # Check that at least two bodies differ (rules out static error pages)
    unique_bodies = {r["body"] for r in responses_200}
    if len(unique_bodies) < 2:
        logger.debug("IDOR check on %s: identical bodies — false positive.", path)
        return None

    evidence_lines: list[str] = []
    for r in responses_200:
        evidence_lines.append(f"  ID {r['id']} → 200 OK ({r['length']} bytes)")

    return {
        "module":   "api_fuzzer",
        "severity": "High",
        "title":    f"Potential IDOR on {path}/<id>",
        "detail":   (
            f"The endpoint {path}/<id> returns distinct records for "
            f"different integer IDs without requiring authentication. "
            f"An attacker could enumerate all records."
        ),
        "evidence": "\n".join(evidence_lines),
    }


# ── Public Interface ────────────────────────────────────────────────────────
def run(target: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    """Discover API endpoints on *target* and test for IDOR.

    Parameters
    ----------
    target : str
        Fully qualified URL (e.g. ``http://127.0.0.1:5000``).
    config : dict
        Parsed ``config.yaml`` contents.

    Returns
    -------
    list[dict]
        A list of finding dicts.
    """
    target = _normalise_target(target)
    timeout: int = config.get("scan_settings", {}).get("default_timeout", 5)
    user_agent: str = config.get("scan_settings", {}).get(
        "user_agent", "SentinelScanner/1.0"
    )
    max_ids: int = config.get("scan_settings", {}).get("max_idor_ids", 5)
    api_paths: list[str] = config.get("api_paths", DEFAULT_API_PATHS)

    findings: list[dict[str, Any]] = []

    # ── Phase 1: Endpoint Discovery ─────────────────────────────────────
    logger.info("Probing %d API paths on %s …", len(api_paths), target)
    discovered = _discover_endpoints(target, api_paths, timeout, user_agent)

    if not discovered:
        logger.info("No live API endpoints found.")
        return findings

    logger.info("Discovered %d live endpoint(s).", len(discovered))

    for ep in discovered:
        findings.append({
            "module":   "api_fuzzer",
            "severity": "Info",
            "title":    f"API Endpoint Found: {ep['path']}",
            "detail":   (
                f"HTTP {ep['status_code']} — {ep['content_length']} bytes. "
                f"Endpoint is reachable without authentication."
            ),
            "evidence": f"GET {target}{ep['path']} → {ep['status_code']}",
        })

    # ── Phase 2: IDOR Fuzzing ───────────────────────────────────────────
    logger.info("Testing discovered endpoints for IDOR (max %d IDs) …", max_ids)
    for ep in discovered:
        idor_finding = _test_idor(
            target=target,
            path=ep["path"],
            max_ids=max_ids,
            timeout=timeout,
            user_agent=user_agent,
        )
        if idor_finding:
            logger.warning(
                "⚠  IDOR detected on %s/<id>", ep["path"],
            )
            findings.append(idor_finding)

    return findings
