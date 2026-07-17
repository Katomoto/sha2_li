from __future__ import annotations

import argparse
import json
from collections import Counter

from sha256_reduced.fig6_analysis import analyze_fig6


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check which Fig. 6 double-bit conditions are recovered from the local analysis pipeline."
    )
    parser.add_argument("--timeout-ms", type=int, default=20_000, help="Per-solver timeout for the optional full model.")
    parser.add_argument(
        "--solver-threads",
        type=int,
        default=None,
        help="Best-effort Z3 thread hint for the optional full model.",
    )
    parser.add_argument(
        "--skip-full-model",
        action="store_true",
        help="Skip the expensive whole-model SMT implication pass and report only witness/Boolean results.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Choose human-readable text or machine-readable JSON output.",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Print every Fig. 6 condition instead of only the non-Boolean remainder.",
    )
    return parser.parse_args()


def _report_payload(report) -> dict[str, object]:
    return {
        "witness_matches_characteristic": report.witness_matches_characteristic,
        "witness_is_collision": report.witness_is_collision,
        "full_model_satisfiable": report.full_model_satisfiable,
        "counts": dict(Counter(result.source for result in report.conditions)),
        "conditions": [
            {
                "condition": str(result.condition),
                "source": result.source,
                "detail": result.detail,
                "full_model_status": result.full_model_status,
                "witness_holds": result.witness_holds,
            }
            for result in report.conditions
        ],
    }


def main() -> int:
    args = _parse_args()
    report = analyze_fig6(
        timeout_ms=args.timeout_ms,
        solver_threads=args.solver_threads,
        run_full_model=not args.skip_full_model,
    )

    if args.format == "json":
        print(json.dumps(_report_payload(report), indent=2, sort_keys=True))
        return 0

    counts = Counter(result.source for result in report.conditions)
    print(f"witness_matches_characteristic: {report.witness_matches_characteristic}")
    print(f"witness_is_collision: {report.witness_is_collision}")
    print(f"full_model_satisfiable: {report.full_model_satisfiable}")
    print(f"condition_counts: {dict(counts)}")

    for result in report.conditions:
        if not args.show_all and result.source == "boolean":
            continue
        print(
            f"{result.condition}: source={result.source}, "
            f"witness_holds={result.witness_holds}, "
            f"full_model={result.full_model_status}, detail={result.detail}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
