"""
Sentinel Web Scanner — Main Engine
===================================
CLI entry-point that loads config, dynamically imports scanning modules,
orchestrates the scan, and triggers reporting / alerting.

Usage:
    python scanner.py --target http://example.com
    python scanner.py --config myconfig.yaml
    python scanner.py --target http://127.0.0.1:5000 --modules header_analyzer api_fuzzer
"""

from __future__ import annotations

import argparse
import importlib
import logging
import sys
import time
from pathlib import Path
from typing import Any

import yaml
from colorama import Fore, Style, init as colorama_init

from utils.reporter import save_json_report
from utils.notifier import send_discord_alert

# ── Logging Setup ───────────────────────────────────────────────────────────
LOG_FORMAT = (
    f"{Fore.CYAN}%(asctime)s{Style.RESET_ALL} "
    f"[%(levelname)s] "
    f"{Fore.YELLOW}%(name)s{Style.RESET_ALL} — %(message)s"
)


def _configure_logging(verbose: bool = False) -> None:
    """Set up the root logger with coloured console output."""
    colorama_init(autoreset=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt="%H:%M:%S")


logger = logging.getLogger("sentinel")

# ── Type Aliases ────────────────────────────────────────────────────────────
Finding = dict[str, Any]
"""
A single finding dict has the shape:
{
    "module":   str,
    "severity": "Info" | "Low" | "Medium" | "High" | "Critical",
    "title":    str,
    "detail":   str,
    "evidence": str | None,
}
"""


# ── Config Loader ──────────────────────────────────────────────────────────
def load_config(path: str | Path) -> dict[str, Any]:
    """Read and return the YAML configuration file."""
    config_path = Path(path)
    if not config_path.is_file():
        logger.error("Config file not found: %s", config_path)
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg: dict[str, Any] = yaml.safe_load(fh)
    logger.debug("Loaded config from %s", config_path)
    return cfg


# ── Module Loader ──────────────────────────────────────────────────────────
def load_module(module_name: str) -> Any:
    """Dynamically import a module from the `modules` package.

    Each module MUST expose a callable:
        run(target: str, config: dict) -> list[Finding]
    """
    fqn = f"modules.{module_name}"
    try:
        mod = importlib.import_module(fqn)
    except ModuleNotFoundError:
        logger.error("Module '%s' not found in modules/ package.", module_name)
        sys.exit(1)
    if not hasattr(mod, "run"):
        logger.error("Module '%s' does not expose a run() function.", module_name)
        sys.exit(1)
    return mod


# ── Banner ──────────────────────────────────────────────────────────────────
BANNER = rf"""
{Fore.RED}
  ____            _   _            _
 / ___|  ___ _ __ | |_(_)_ __   ___| |
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
  ___) |  __/ | | | |_| | | | |  __/ |
 |____/ \___|_| |_|\__|_|_| |_|\___|_|
{Style.RESET_ALL}
 {Fore.WHITE}Web Vulnerability Scanner v1.0{Style.RESET_ALL}
 {Fore.LIGHTBLACK_EX}─────────────────────────────────────{Style.RESET_ALL}
"""


# ── CLI ─────────────────────────────────────────────────────────────────────
def build_cli() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel — Modern Web Vulnerability Scanner",
    )
    parser.add_argument(
        "--target", "-t",
        type=str,
        default=None,
        help="Target URL to scan (overrides config.yaml).",
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="config.yaml",
        help="Path to the YAML config file (default: config.yaml).",
    )
    parser.add_argument(
        "--modules", "-m",
        nargs="*",
        default=None,
        help="Space-separated list of modules to run (overrides config.yaml).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug-level logging.",
    )
    return parser.parse_args()


# ── Main Orchestrator ───────────────────────────────────────────────────────
def main() -> None:
    """Entry-point: parse args, load config, run modules, report."""
    args = build_cli()
    _configure_logging(verbose=args.verbose)
    print(BANNER)

    # ── Load configuration ──────────────────────────────────────────────
    config = load_config(args.config)

    target: str = args.target or config.get("target", "")
    if not target:
        logger.error("No target URL specified. Use --target or set it in config.yaml.")
        sys.exit(1)

    module_names: list[str] = args.modules or config.get("modules", [])
    if not module_names:
        logger.error("No modules specified. Use --modules or set them in config.yaml.")
        sys.exit(1)

    logger.info(
        "%sTarget:%s  %s",
        Fore.GREEN, Style.RESET_ALL, target,
    )
    logger.info(
        "%sModules:%s %s",
        Fore.GREEN, Style.RESET_ALL, ", ".join(module_names),
    )
    print()

    # ── Run each module ─────────────────────────────────────────────────
    all_findings: list[Finding] = []
    scan_start = time.time()

    for name in module_names:
        logger.info(
            "%s── Running module: %s%s%s ──%s",
            Fore.MAGENTA, Fore.WHITE, name, Fore.MAGENTA, Style.RESET_ALL,
        )
        mod = load_module(name)
        try:
            findings: list[Finding] = mod.run(target=target, config=config)
            all_findings.extend(findings)
            logger.info(
                "  ↳ %s produced %s%d%s finding(s).",
                name, Fore.YELLOW, len(findings), Style.RESET_ALL,
            )
        except Exception:
            logger.exception("Module '%s' raised an unhandled exception.", name)
        print()

    scan_duration = round(time.time() - scan_start, 2)

    # ── Summary ─────────────────────────────────────────────────────────
    severity_counts: dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    sev_color_map: dict[str, str] = {
        "Critical": Fore.LIGHTRED_EX,
        "High": Fore.RED,
        "Medium": Fore.YELLOW,
        "Low": Fore.CYAN,
        "Info": Fore.LIGHTBLACK_EX,
    }

    print(f"{Fore.WHITE}{'═' * 50}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  SCAN COMPLETE — {scan_duration}s{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'═' * 50}{Style.RESET_ALL}")
    for sev, count in sorted(severity_counts.items(), key=lambda x: x[0]):
        color = sev_color_map.get(sev, "")
        print(f"  {color}{sev:10s}{Style.RESET_ALL}  {count}")
    print(f"  {'─' * 30}")
    print(f"  {'Total':10s}  {len(all_findings)}")
    print()

    # ── Reporting ───────────────────────────────────────────────────────
    report_path = save_json_report(
        target=target,
        findings=all_findings,
        duration=scan_duration,
        modules=module_names,
    )
    logger.info(
        "%sReport saved:%s %s",
        Fore.GREEN, Style.RESET_ALL, report_path,
    )

    # ── Discord Alerting ────────────────────────────────────────────────
    webhook_url: str = config.get("discord_webhook", "")
    high_findings = [f for f in all_findings if f.get("severity") in ("High", "Critical")]

    if webhook_url and high_findings:
        send_discord_alert(
            webhook_url=webhook_url,
            target=target,
            findings=high_findings,
        )
    elif high_findings:
        logger.warning(
            "Found %d High/Critical finding(s) but no Discord webhook is configured.",
            len(high_findings),
        )

    logger.info("Done. 🛡️")


if __name__ == "__main__":
    main()
