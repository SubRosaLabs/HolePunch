#!/usr/bin/env python3
"""Publish a verified, already-tagged build to the public GitHub Releases page.

No tag or source commit is created here. Failures leave the draft intact for
inspection rather than deleting or silently replacing an existing release.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from verify_release import expected_names, verify

GITHUB_REPO = "SubRosaLabs/HolePunch"
GITHUB_API = "https://api.github.com"
GITHUB_UPLOAD = "https://uploads.github.com"
TAG_PATTERN = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.]+)?\Z")


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).strip()


def tagged_commit(remote: str, tag: str) -> str:
    rows = git("ls-remote", remote, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
    refs = dict((ref, sha) for sha, ref in (line.split() for line in rows.splitlines()))
    return refs.get(f"refs/tags/{tag}^{{}}", refs.get(f"refs/tags/{tag}", ""))


def check_preflight(tag: str, directory: Path, notes_file: Path) -> tuple[str, list[Path], str]:
    if not TAG_PATTERN.fullmatch(tag):
        raise ValueError("tag must be a semantic version such as v0.1.0")
    if git("status", "--porcelain"):
        raise ValueError("source worktree is not clean")
    commit = git("rev-parse", "HEAD")
    local_tag = git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    if local_tag != commit:
        raise ValueError(f"{tag} does not identify checked-out HEAD")
    public_sha = tagged_commit(f"https://github.com/{GITHUB_REPO}.git", tag)
    if public_sha != commit:
        raise ValueError(f"tag mismatch: local={commit} public={public_sha or 'missing'}")
    expected = "".join(verify(directory))
    if (directory / "SHA256SUMS").read_text(encoding="ascii") != expected:
        raise ValueError("SHA256SUMS does not match the binary contents")
    notes = notes_file.read_text(encoding="utf-8").strip()
    if not notes:
        raise ValueError("release notes must not be empty")
    assets = [directory / name for name in sorted(expected_names())] + [directory / "SHA256SUMS"]
    return commit, assets, notes


def request(url: str, token: str, *, method: str = "GET", data: bytes | None = None,
            content_type: str | None = None) -> Any:
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        # Tokens stay in headers; do not dump response bodies or authentication details.
        path = urllib.parse.urlsplit(url).path
        raise RuntimeError(f"{method} {path} failed: HTTP {exc.code}") from None


def github_token() -> str:
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    if token:
        return token
    result = subprocess.run(["gh", "auth", "token"], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, check=True)
    return result.stdout.strip()


def upload_asset(token: str, release_id: int, asset: Path) -> None:
    query = urllib.parse.urlencode({"name": asset.name})
    request(f"{GITHUB_UPLOAD}/repos/{GITHUB_REPO}/releases/{release_id}/assets?{query}",
            token, method="POST", data=asset.read_bytes(), content_type="application/octet-stream")


def verify_assets(base: str, token: str, release_id: int, assets: list[Path]) -> None:
    found = request(f"{base}/releases/{release_id}/assets?per_page=100", token)
    expected = {p.name: p.stat().st_size for p in assets}
    actual = {item["name"]: item["size"] for item in found}
    if actual != expected:
        raise RuntimeError(f"asset metadata mismatch on release {release_id}")


def publish(tag: str, commit: str, assets: list[Path], notes: str) -> str:
    base = f"{GITHUB_API}/repos/{GITHUB_REPO}"
    token = github_token()
    try:
        existing = request(f"{base}/releases/tags/{urllib.parse.quote(tag)}", token)
    except RuntimeError as exc:
        if "HTTP 404" not in str(exc):
            raise
    else:
        raise RuntimeError(f"release already exists at {existing.get('html_url', base)}; inspect it before retrying")

    body = {"tag_name": tag, "name": tag, "body": notes, "draft": True,
            "prerelease": "-" in tag, "target_commitish": commit}
    release = request(f"{base}/releases", token, method="POST", data=json.dumps(body).encode(),
                      content_type="application/json")
    print(f"Draft created: {release.get('html_url')} (id {release['id']})", flush=True)
    for asset in assets:
        upload_asset(token, release["id"], asset)
        print(f"Uploaded {asset.name}", flush=True)
    verify_assets(base, token, release["id"], assets)
    print("Draft asset list matches by name and size; publishing", flush=True)

    body["draft"] = False
    url = f"{base}/releases/{release['id']}"
    request(url, token, method="PATCH", data=json.dumps(body).encode(), content_type="application/json")
    current = request(url, token)
    if current.get("draft") or current.get("tag_name") != tag:
        raise RuntimeError("release did not publish correctly")
    verify_assets(base, token, release["id"], assets)
    print(f"Published and read back {current['html_url']}", flush=True)
    return current["html_url"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="existing tag on public GitHub")
    parser.add_argument("--notes-file", required=True, type=Path)
    parser.add_argument("--directory", type=Path, default=Path("bin/release"))
    parser.add_argument("--publish", action="store_true", help="create and publish the release")
    args = parser.parse_args()
    try:
        commit, assets, notes = check_preflight(args.tag, args.directory, args.notes_file)
        if not args.publish:
            print(f"DRY RUN: {args.tag} -> {commit}; {len(assets)} verified assets; public tag matches. "
                  "Use --publish to create the release.")
            return 0
        publish(args.tag, commit, assets, notes)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"release failed: {exc}", file=sys.stderr)
        print("If a draft was created, inspect it before retrying; this tool never deletes it.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
