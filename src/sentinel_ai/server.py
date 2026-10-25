"""Run the local dashboard, bound to loopback by default."""

from __future__ import annotations

import argparse

import uvicorn

from .api import app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-ai-dashboard", description="Run the loopback-only Sentinel AI dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (loopback is required by the application policy)")
    parser.add_argument("--port", type=int, default=4173)
    parser.add_argument("--reload", action="store_true", help="Enable code reload for local development")
    args = parser.parse_args(argv)
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("Sentinel AI dashboard only supports loopback bind addresses.")
    if not app.state.store.has_users():
        print("\nSentinel AI first-run setup", flush=True)
        print(f"One-time bootstrap token: {app.state.bootstrap_token}", flush=True)
        print("Enter this token in the dashboard. It is valid until the first owner is created.\n", flush=True)
    print(f"Sentinel AI dashboard: http://{args.host}:{args.port}/", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
