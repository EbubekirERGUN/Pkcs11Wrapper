#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path

REQUIRED_CHECKS = [
    ("Login succeeded.", []),
    ("Encrypt/decrypt smoke:", ["roundTrip=True"]),
    ("Multipart smoke:", ["roundTrip=True"]),
    ("Digest smoke:", ["matchesMultipart=True"]),
    ("Random smoke:", ["allZero=False", "distinct=True"]),
    ("Sign/verify smoke:", ["verified=True", "invalidVerified=False"]),
    ("Multipart sign/verify smoke:", ["matchesSinglePart=True", "verified=True", "invalidVerified=False", "shortVerified=False"]),
    ("Object lifecycle destroy:", ["foundAfterDestroy=False"]),
    ("Generate key smoke:", ["roundTrip=True"]),
    ("Generate key pair smoke:", ["publicMatch=True", "privateMatch=True", "verified=True"]),
    ("Wrap/unwrap smoke:", ["roundTrip=True"]),
    ("Derive key smoke:", ["roundTrip=True"]),
    ("Logout succeeded.", []),
]

OPTIONAL_CAPABILITY_CHECKS = [
    (("Operation-state smoke:", ["matchesBaseline=True"]), "  Operation-state smoke skipped: module reports operation state as unavailable."),
]

SKIP_PREFIXES = [
    "  Login skipped:",
    "  Encrypt/decrypt skipped:",
    "  Multipart skipped:",
    "  Sign/verify skipped:",
    "  Digest skipped:",
    "  Random skipped:",
    "  Wrap/unwrap skipped:",
]

FAIL_PREFIXES = [
    "Smoke test failed:",
    "  Login/logout failed:",
    "  Encrypt/decrypt failed:",
    "  Multipart/operation-state failed:",
    "  Sign/verify failed:",
    "  Digest failed:",
    "  Random failed:",
    "  Object lifecycle failed:",
    "  Key generation smoke failed:",
    "  Wrap/unwrap failed:",
    "  Derive key smoke failed:",
]


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: validate-smoke-output.py <smoke-log>", file=sys.stderr)
        return 2

    log_path = Path(sys.argv[1])
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()

    failures: list[str] = []

    for prefix in FAIL_PREFIXES:
        matching_line = find_line(lines, prefix)
        if matching_line:
            failures.append(f"smoke output contains failure marker: {matching_line}")

    for prefix in SKIP_PREFIXES:
        matching_line = find_line(lines, prefix)
        if matching_line:
            failures.append(f"smoke output contains strict-skip marker: {matching_line}")

    for prefix, fragments in REQUIRED_CHECKS:
        matching_line = find_line(lines, prefix)
        if not matching_line:
            failures.append(f"missing required smoke line with prefix: {prefix}")
            continue

        for fragment in fragments:
            if fragment not in matching_line:
                failures.append(f"smoke line '{matching_line}' is missing required fragment '{fragment}'")

    for (prefix, fragments), accepted_skip_prefix in OPTIONAL_CAPABILITY_CHECKS:
        matching_line = find_line(lines, prefix)
        if matching_line:
            for fragment in fragments:
                if fragment not in matching_line:
                    failures.append(f"smoke line '{matching_line}' is missing required fragment '{fragment}'")
            continue

        accepted_skip = find_line(lines, accepted_skip_prefix)
        if not accepted_skip:
            failures.append(
                f"missing capability result: expected '{prefix}' or accepted skip '{accepted_skip_prefix}'"
            )

    if failures:
        print("Smoke validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("Smoke validation succeeded.")
    return 0


def find_line(lines: list[str], prefix: str) -> str | None:
    for line in lines:
        if prefix in line:
            return line
    return None


if __name__ == "__main__":
    raise SystemExit(main())
