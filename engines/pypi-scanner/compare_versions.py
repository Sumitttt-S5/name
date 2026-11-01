
import argparse
import json
import sys
from pathlib import Path

SCANNER_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(SCANNER_ROOT))

from scanner.version_diff import compare_versions


def main():
    parser = argparse.ArgumentParser(
        description="Compare two Python package versions for security-relevant changes."
    )

    parser.add_argument("--baseline", required=True, help="Older package directory")
    parser.add_argument("--candidate", required=True, help="Newer package directory")
    parser.add_argument("--baseline-version", required=True, help="Older package version")
    parser.add_argument("--candidate-version", required=True, help="Newer package version")
    parser.add_argument(
        "--output",
        default="reports/version-diff.json",
        help="Output JSON report path",
    )

    args = parser.parse_args()

    try:
        result = compare_versions(
            baseline_path=args.baseline,
            candidate_path=args.candidate,
            baseline_version=args.baseline_version,
            candidate_version=args.candidate_version,
        )

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )

        print("\n=== SUPPLY CHAIN GUARDIAN: VERSION COMPARISON ===")
        print(f"Baseline version: {args.baseline_version}")
        print(f"Candidate version: {args.candidate_version}")
        print(f"Comparison status: {result['status']}")
        print(
            "New behaviours:",
            result["summary"]["introduced_behaviours"],
        )
        print(
            "Removed behaviours:",
            result["summary"]["removed_behaviours"],
        )
        print(
            "Persistent behaviours:",
            result["summary"]["persistent_behaviours"],
        )
        print(f"\nReport saved to: {output_path.resolve()}")

        return 0

    except (ValueError, OSError) as error:
        print(f"Comparison failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
