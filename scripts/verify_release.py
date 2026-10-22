#!/usr/bin/env python3
"""Fail a release if its expected artifacts or plaintext identifiers are wrong."""

import hashlib
import sys
from pathlib import Path


TARGETS = (
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("windows", "amd64"),
)
ROLES = ("server", "client")
# These checks are deliberate release fingerprints, not a secrecy guarantee.
FORBIDDEN = (
    b"HolePunch",
    b"HolePunched",
    b"github.com/",
    b"golang.org/",
    b"mvdan.cc/",
    b"SubRosaLabs",
)


def expected_names() -> set[str]:
    return {
        f"holepunch-{role}-{os_name}-{arch}{'.exe' if os_name == 'windows' else ''}"
        for os_name, arch in TARGETS
        for role in ROLES
    }


def verify(directory: Path) -> list[str]:
    expected = expected_names()
    actual = {p.name for p in directory.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
    if actual != expected:
        raise ValueError(f"release assets mismatch: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}")

    checksums = []
    for name in sorted(expected):
        path = directory / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise ValueError(f"invalid binary: {path}")
        data = path.read_bytes()
        present = [term.decode("ascii") for term in FORBIDDEN if term in data]
        if present:
            raise ValueError(f"plaintext fingerprint(s) in {name}: {', '.join(present)}")
        checksums.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
    return checksums


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_release.py <release-directory>", file=sys.stderr)
        return 2
    directory = Path(sys.argv[1])
    if not directory.is_dir():
        print(f"not a directory: {directory}", file=sys.stderr)
        return 2
    try:
        checksums = verify(directory)
    except ValueError as exc:
        print(f"release validation failed: {exc}", file=sys.stderr)
        return 1
    (directory / "SHA256SUMS").write_text("".join(checksums), encoding="ascii")
    print(f"Verified {len(checksums)} obfuscated binaries; wrote {directory / 'SHA256SUMS'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
