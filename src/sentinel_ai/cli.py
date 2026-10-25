"""Command-line entry point for local Phase 1 assessments."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from .browser import BrowserController
from .models import AuthorizationRecord, ScanLimits
from .report import write_html_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-ai",
        description="Run a bounded, passive assessment in a visible Chromium browser.",
    )
    parser.add_argument("--target", required=True, help="Authorized starting HTTP(S) URL")
    parser.add_argument("--authorization-file", required=True, type=Path, help="JSON authorization record")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"), help="Local output directory")
    parser.add_argument("--max-pages", type=int, default=10)
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-requests", type=int, default=500)
    parser.add_argument("--max-duration-seconds", type=int, default=300)
    parser.add_argument("--request-delay-seconds", type=float, default=0.1)
    parser.add_argument("--navigation-delay-seconds", type=float, default=0.5)
    parser.add_argument("--navigation-timeout-ms", type=int, default=20_000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        authorization = AuthorizationRecord.model_validate_json(args.authorization_file.read_text(encoding="utf-8"))
        limits = ScanLimits(
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            max_requests=args.max_requests,
            max_duration_seconds=args.max_duration_seconds,
            request_delay_seconds=args.request_delay_seconds,
            navigation_delay_seconds=args.navigation_delay_seconds,
            navigation_timeout_ms=args.navigation_timeout_ms,
        )
    except OSError as exc:
        print(f"Cannot read authorization file: {exc}", file=sys.stderr)
        return 2
    except (ValidationError, json.JSONDecodeError) as exc:
        print(f"Invalid authorization or scan limits: {exc}", file=sys.stderr)
        return 2

    controller = BrowserController(authorization, args.target, args.output_dir, limits)
    try:
        result = controller.run()
    except KeyboardInterrupt:
        controller.emergency_stop()
        print("Assessment interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Assessment failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    json_path = args.output_dir / "assessment.json"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    html_path = write_html_report(result, args.output_dir / "report.html")
    print(f"Assessment complete: {len(result.pages)} page(s), {len(result.findings)} finding(s)")
    print(f"HTML report: {html_path.resolve()}")
    print(f"Structured data: {json_path.resolve()}")
    print(f"Activity log: {(args.output_dir / 'activity.jsonl').resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
