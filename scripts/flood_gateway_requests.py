#!/usr/bin/env python3
"""Send repeated authenticated GETs to the ShieldGate gateway to populate request_logs (dashboard metrics).

Requires DATABASE_URL on the gateway so rows are persisted.

Environment:
  GATEWAY_URL   Base URL with no trailing slash (e.g. https://shieldgate-gateway.onrender.com)
  ACCESS_TOKEN  JWT from POST {GATEWAY_URL}/auth/login (do not commit this value)

Example:
  export GATEWAY_URL=https://shieldgate-gateway.onrender.com
  export ACCESS_TOKEN=eyJ...
  python scripts/flood_gateway_requests.py --count 50

Optional: --path /proxy/ping (needs working DOWNSTREAM_URL); default is GET / (requires Bearer).
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="Number of requests (default: 50)",
    )
    parser.add_argument(
        "--path",
        default="/",
        help="Request path (default: /). Example: /proxy/ping",
    )
    parser.add_argument(
        "--gateway-url",
        default="",
        help="Override GATEWAY_URL env",
    )
    parser.add_argument(
        "--access-token",
        default="",
        help="Override ACCESS_TOKEN env (prefer env to avoid shell history)",
    )
    args = parser.parse_args()

    base = (args.gateway_url or os.environ.get("GATEWAY_URL", "")).rstrip("/")
    token = args.access_token or os.environ.get("ACCESS_TOKEN", "")

    if not base:
        print("error: set GATEWAY_URL or pass --gateway-url", file=sys.stderr)
        return 1
    if not token:
        print(
            "error: set ACCESS_TOKEN or pass --access-token "
            f"(obtain via POST {base}/auth/login with email/password)",
            file=sys.stderr,
        )
        return 1

    path = args.path if args.path.startswith("/") else f"/{args.path}"
    url = f"{base}{path}"

    ok = 0
    for i in range(args.count):
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                code = resp.getcode()
                if 200 <= code < 300:
                    ok += 1
                print(f"{i + 1}/{args.count} {url} -> {code}")
        except urllib.error.HTTPError as e:
            print(f"{i + 1}/{args.count} {url} -> HTTP {e.code}: {e.reason}", file=sys.stderr)
        except urllib.error.URLError as e:
            print(f"{i + 1}/{args.count} {url} -> error: {e.reason}", file=sys.stderr)

    print(f"done: {ok}/{args.count} requests returned 2xx")
    return 0 if ok == args.count else 2


if __name__ == "__main__":
    raise SystemExit(main())
