"""Fail-closed CLI; stdout metadata never contains the submitted URL or body."""
import argparse
import json
import os
from pathlib import Path
import sys

from . import CircuitLockError, Policy, safe_fetch


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CircuitLock — policy-controlled outbound HTTP(S)")
    parser.add_argument("url", help="Destination URL (not repeated in reports)")
    parser.add_argument("--policy", help="JSON egress policy. Default: public HTTPS on 443 only")
    parser.add_argument("--output", help="Create new output file exclusively (mode 0600)")
    parser.add_argument("--head", action="store_true", help="Issue a HEAD request")
    args = parser.parse_args(argv)
    try:
        policy = Policy.from_file(args.policy) if args.policy else Policy()
        result = safe_fetch(args.url, policy, method="HEAD" if args.head else "GET")
        if args.output:
            file = Path(args.output)
            fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(result.content)
            except BaseException:
                file.unlink(missing_ok=True)
                raise
        print(json.dumps({"status": result.status, "bytes": result.size,
                          "sha256": result.sha256, "redirects": result.redirects,
                          "host": result.final_host, "content_type": result.content_type,
                          "written": bool(args.output)}, sort_keys=True))
        return 0
    except (CircuitLockError, OSError, ValueError) as e:
        # Do NOT print exception details from untrusted URLs or network stacks.
        print("CircuitLock: request denied or incomplete (no output admitted).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
