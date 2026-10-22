"""Offline tests for fingerprint validation and draft-release publication."""

import contextlib
import http.server
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_release as publisher
import verify_release as verifier


def fake_assets(directory: Path) -> list[Path]:
    assets = []
    for name in sorted(verifier.expected_names()):
        p = directory / name
        p.write_bytes(b"\x7fELF\x00test-" + name.encode())
        assets.append(p)
    (directory / "SHA256SUMS").write_text("".join(verifier.verify(directory)), encoding="ascii")
    return assets + [directory / "SHA256SUMS"]


class ReleaseVerificationTests(unittest.TestCase):
    def test_missing_and_plaintext_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temp:
            d = Path(temp)
            with self.assertRaisesRegex(ValueError, "missing="):
                verifier.verify(d)
            fake_assets(d)
            self.assertEqual(len(verifier.verify(d)), 10)
            (d / sorted(verifier.expected_names())[0]).write_bytes(b"Go build info github.com/quic-go/quic-go")
            with self.assertRaisesRegex(ValueError, "github.com/"):
                verifier.verify(d)

    def test_public_tag_mismatch_blocks_publication(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temp:
            d = Path(temp) / "assets"
            d.mkdir()
            fake_assets(d)
            notes = Path(temp) / "notes.md"
            notes.write_text("Notes for testing", encoding="utf-8")
            def git_side_effect(*args):
                if args[0] == "status":
                    return ""
                return "a" * 40
            with mock.patch.object(publisher, "git", side_effect=git_side_effect), mock.patch.object(
                publisher, "tagged_commit", return_value="b" * 40
            ):
                with self.assertRaisesRegex(ValueError, "tag mismatch"):
                    publisher.check_preflight("v0.1.0", d, notes)


class FakeReleases(http.server.BaseHTTPRequestHandler):
    state: dict = {}

    def log_message(self, format: str, *args: object) -> None:
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def serve_request(self):
        path = urlsplit(self.path)
        rel = self.state
        if path.path.endswith("/releases/tags/v0.1.0"):
            self.send_json({"message": "not found"}, 404)
            return
        if path.path.endswith("/releases") and self.command == "POST":
            assert self.headers["Authorization"] == "Bearer gh-test"
            rel.update(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            rel.update({"id": 1, "html_url": "https://example.invalid/release", "assets": {}})
            self.send_json(rel, 201)
            return
        if path.path.endswith("/assets") and self.command == "POST":
            assert self.headers["Authorization"] == "Bearer gh-test"
            body = self.rfile.read(int(self.headers["Content-Length"]))
            name = parse_qs(path.query)["name"][0]
            rel["assets"][name] = len(body)
            self.send_json({"name": name, "size": len(body)}, 201)
            return
        if path.path.endswith("/assets") and self.command == "GET":
            self.send_json([{"name": n, "size": s} for n, s in rel["assets"].items()])
            return
        if "/releases/" in path.path and self.command == "PATCH":
            rel.update(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_json(rel)
            return
        if "/releases/" in path.path and self.command == "GET":
            self.send_json(rel)
            return
        self.send_json({"message": "unexpected route"}, 404)

    do_GET = serve_request
    do_POST = serve_request
    do_PATCH = serve_request


class PublicationTests(unittest.TestCase):
    def test_draft_assets_publish_and_readback(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temp:
            assets = fake_assets(Path(temp))
            state = {}
            class Handler(FakeReleases):
                pass
            Handler.state = state
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"http://127.0.0.1:{server.server_port}"
            try:
                with mock.patch.object(publisher, "GITHUB_API", url), mock.patch.object(
                    publisher, "GITHUB_UPLOAD", url
                ), mock.patch.object(publisher, "github_token", return_value="gh-test"), contextlib.redirect_stdout(io.StringIO()):
                    result = publisher.publish("v0.1.0", "a" * 40, assets, "Release notes")
                self.assertEqual(result, "https://example.invalid/release")
                self.assertFalse(state["draft"])
                self.assertEqual(len(state["assets"]), 11)
                self.assertEqual(state["tag_name"], "v0.1.0")
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()


if __name__ == "__main__":
    unittest.main()
