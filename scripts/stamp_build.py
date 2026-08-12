"""Stamp core/build_info.py during an image build.

Run by the Dockerfile, never by hand. Turning a source checkout into a release build is
a property of the *pipeline*, not of a developer's working copy — see core/build_info.py
for why enforcement must not be an environment variable.

    python scripts/stamp_build.py --version 1.4.0 --commit abc123 --licensed-to "Acme"
"""

from __future__ import annotations

import argparse
import pathlib
import re
from datetime import UTC, datetime

TARGET = pathlib.Path(__file__).resolve().parents[1] / "core" / "build_info.py"


def _set(text: str, name: str, value: str | bool) -> str:
    literal = repr(value)
    pattern = rf"^{name}: (bool|str) = .*$"
    kind = "bool" if isinstance(value, bool) else "str"
    replacement = f"{name}: {kind} = {literal}"
    new, count = re.subn(pattern, replacement, text, count=1, flags=re.M)
    if count != 1:
        raise SystemExit(f"stamp_build: could not find {name} in {TARGET}")
    return new


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="dev")
    ap.add_argument("--commit", default="unknown")
    args = ap.parse_args()

    text = TARGET.read_text()
    text = _set(text, "VERSION", args.version)
    text = _set(text, "COMMIT", args.commit)
    text = _set(text, "BUILT_AT", datetime.now(UTC).isoformat(timespec="seconds"))
    TARGET.write_text(text)
    print(f"stamped build_info: version={args.version} commit={args.commit}")


if __name__ == "__main__":
    main()
