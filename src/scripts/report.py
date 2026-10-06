"""Terminal incident report.

Doubles as the contingency demo: if the dashboard is unavailable, this shows the
whole pipeline -- reduction, tiers, campaigns and evidence -- in one screen.

Run: python -m src.scripts.report
"""

from __future__ import annotations

import argparse
import sys

from src.backend.config import EVENTS_CSV
from src.backend.pipeline import analyze

TIER_COLOUR = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _colour(text: str, tier: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{TIER_COLOUR.get(tier, '')}{text}{RESET}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SprayTrace incident report")
    parser.add_argument("csv", nargs="?", default=str(EVENTS_CSV))
    parser.add_argument("--no-colour", action="store_true")
    parser.add_argument("--no-model", action="store_true",
                        help="rules only, skipping the Isolation Forest")
    args = parser.parse_args(argv)

    colour = not args.no_colour and sys.stdout.isatty()
    analysis = analyze(args.csv, use_model=not args.no_model)
    summary = analysis.summary

    print(f"\n{BOLD if colour else ''}SprayTrace — incident report{RESET if colour else ''}")
    print(f"source: {args.csv}  ({summary['source_format']} format)")
    print("─" * 78)

    reduction = (
        f"{summary['total_events']:,} events → {summary['escalated']} escalatable "
        f"→ {summary['campaigns']} campaigns"
    )
    print(f"{BOLD if colour else ''}{reduction}{RESET if colour else ''}")
    tiers = summary["by_tier"]
    print(
        f"  critical {tiers['critical']}  high {tiers['high']}  "
        f"medium {tiers['medium']}  suppressed {summary['suppressed']:,} "
        f"(audit log only)"
    )
    print("─" * 78)

    if analysis.campaigns.empty:
        print("\nNo campaigns above the escalation gate.")
        return 0

    for _, campaign in analysis.campaigns.iterrows():
        header = (
            f"{campaign['campaign_id']} · {campaign['tier'].upper()} · "
            f"risk {campaign['risk']:.2f}"
        )
        print(f"\n{_colour(header, campaign['tier'], colour)}")
        print(f"  {campaign['name']}  [{campaign['technique']}]")
        print(
            f"  {campaign['event_count']} events · "
            f"{len(campaign['usernames'])} accounts · "
            f"{len(campaign['source_ips'])} source(s) · "
            f"{campaign['span_minutes']:.0f} min"
        )
        if campaign["success_count"]:
            print(f"  ⚠ {campaign['success_count']} successful sign-in(s) in window")
        print(f"  {campaign['evidence']}")

    print("\n" + "─" * 78)
    print("Suppressed events are retained for retrospective hunting, not discarded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
