#!/usr/bin/env python3
"""Install a packaged release with scripts/install.sh into an isolated HOME and use it offline.

usage: release_smoke.py dist/kaist-mail-vX.Y.Z-TARGET.tar.gz
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

CHECKOUT = Path(__file__).resolve().parent.parent
FIXTURES = CHECKOUT / "tests" / "fixtures"
INSTALLER = CHECKOUT / "scripts" / "install.sh"
MAIL_ID = "4460000000000000001"
JSON = "application/json;charset=UTF-8"


def run(
    args: list[str], env: dict[str, str], cwd: Path, success: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args, env=env, cwd=cwd, capture_output=True, text=True, timeout=60, check=False
    )
    if (result.returncode == 0) != success:
        raise SystemExit(
            f"{args[1:]}: exit {result.returncode}\n{result.stdout}{result.stderr}"
        )
    return result


def install(
    releases: str,
    version: str,
    home: Path,
    cwd: Path,
    success: bool = True,
    script: Path = INSTALLER,
) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "KAIST_MAIL_RELEASES": releases,
        "KAIST_MAIL_VERSION": version,
    }
    return run(["bash", str(script)], env, cwd, success)


def mirror(root: Path, archive: Path, version: str, corrupt: bool = False) -> Path:
    """A file:// copy of the GitHub releases layout holding `archive` and its checksum."""
    download = root / "download" / version
    download.mkdir(parents=True)
    _ = shutil.copy(archive, download)
    _ = shutil.copy(archive.with_name(archive.name + ".sha256"), download)
    if corrupt:
        copy = download / archive.name
        data = bytearray(copy.read_bytes())
        data[len(data) // 2] ^= 1
        _ = copy.write_bytes(data)
    return root


def fixture_server() -> tuple[ThreadingHTTPServer, dict[int, bytes], list[str]]:
    """Dooray's mail API serving the synthetic test fixtures.

    Returns the server, the attachment bytes it serves by part number, and the
    requests it could not route.
    """
    detail = (FIXTURES / "mail-detail.json").read_bytes()
    attachments: dict[str, tuple[int, bytes]] = {
        urlsplit(f["downloadUrl"]).path: (
            f["partNumber"],
            bytes((i * 31 + f["partNumber"]) % 256 for i in range(f["size"])),
        )
        for f in json.loads(detail)["result"]["content"]["fileList"]
    }
    unexpected: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            url = urlsplit(self.path)
            content_type = JSON
            if url.path == "/v2/wapi/mail-folders":
                kind = parse_qs(url.query)["type"][0]
                body = (FIXTURES / f"mail-folders-{kind}.json").read_bytes()
            elif url.path == "/v2/wapi/mails":
                page = json.loads((FIXTURES / "mails-list.json").read_bytes())
                size = int(parse_qs(url.query)["size"][0])
                page["result"]["contents"] = page["result"]["contents"][:size]
                body = json.dumps(page).encode()
            elif url.path == f"/v2/wapi/mails/{MAIL_ID}":
                body = detail
            elif url.path in attachments:
                body, content_type = (
                    attachments[url.path][1],
                    "application/octet-stream",
                )
            else:
                unexpected.append(f"{self.command} {self.path}")
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            _ = self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, dict(attachments.values()), unexpected


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    archive = Path(sys.argv[1]).resolve()
    version = archive.name.removeprefix("kaist-mail-").split("-")[0]
    with tempfile.TemporaryDirectory(prefix="kaist-mail-smoke-") as directory:
        root = Path(directory)

        releases = mirror(root / "releases", archive, version).as_uri()
        tampered = mirror(root / "tampered", archive, version, corrupt=True).as_uri()

        def refused(case: str, releases: str, reason: str) -> Path:
            """Run the installer in a fresh HOME, expecting it to refuse for `reason`."""
            home = root / case
            result = install(releases, version, home, root, success=False)
            if reason not in result.stderr:
                raise SystemExit(
                    f"{case}: refused for another reason:\n{result.stderr}"
                )
            return home / ".local" / "bin" / "kaist-mail"

        if refused("tampered", tampered, "checksum verification failed").exists():
            raise SystemExit("installer left a binary from a corrupted archive")
        for case, url in [
            ("plain-http", "http://github.com/AidenGeunGeun/kaist-mail/releases"),
            ("loopback-userinfo", "http://127.0.0.1:80@github.com/releases"),
        ]:
            _ = refused(case, url, "must be https://")
        (root / "directory" / ".local" / "bin" / "kaist-mail").mkdir(parents=True)
        _ = refused("directory", releases, "is not a regular file")
        victim = root / "symlink" / "victim"
        victim.parent.mkdir()
        _ = victim.write_text("victim")
        (root / "symlink" / ".local" / "bin").mkdir(parents=True)
        (root / "symlink" / ".local" / "bin" / "kaist-mail").symlink_to(victim)
        _ = refused("symlink", releases, "is not a regular file")
        if victim.read_text() != "victim":
            raise SystemExit("installer wrote through a symlink")

        truncated = root / "truncated.sh"
        _ = truncated.write_text(INSTALLER.read_text().rstrip("\n").rsplit("\n", 1)[0])
        partial = install(releases, version, root / "truncated", root, script=truncated)
        if partial.stdout or partial.stderr or (root / "truncated").exists():
            raise SystemExit("a truncated installer did something")

        home = root / "home"
        installed = install(releases, version, home, root)
        if "is not on your PATH" not in installed.stdout:
            raise SystemExit(
                f"installer did not report the missing PATH entry:\n{installed.stdout}"
            )
        binary = str(home / ".local" / "bin" / "kaist-mail")
        env = {"PATH": "/usr/bin:/bin", "HOME": str(home)}

        def cli(*args: str, success: bool = True, extra: dict[str, str] | None = None):
            return run([binary, *args], {**env, **(extra or {})}, root, success)

        def envelope(
            *args: str, success: bool = True, extra: dict[str, str] | None = None
        ):
            result = cli("--json", *args, success=success, extra=extra)
            stream, other = (
                (result.stdout, result.stderr)
                if success
                else (result.stderr, result.stdout)
            )
            value = json.loads(stream)
            if other or value["ok"] != success:
                raise SystemExit(
                    f"{args}: JSON envelope disagrees with exit status: {result}"
                )
            return value, result.returncode

        if cli("--version").stdout.strip() != f"kaist-mail {version[1:]}":
            raise SystemExit("installed binary version does not match the archive name")
        if envelope("--version")[0]["data"]["version"] != version[1:]:
            raise SystemExit("human and JSON versions disagree")
        if "Workflow:" not in cli("--help").stdout:
            raise SystemExit("--help lost its workflow section")
        usage, code = envelope("list", "--bogus", success=False)
        if (usage["error"]["code"], code) != ("USAGE", 2):
            raise SystemExit(f"usage error: {usage} exit {code}")
        if envelope("auth", "status")[0]["data"]["configured"] is not False:
            raise SystemExit("a fresh HOME reports a session")
        missing, code = envelope("folders", success=False)
        if (missing["error"]["code"], code) != ("AUTH_REQUIRED", 10):
            raise SystemExit(f"folders without a session: {missing} exit {code}")

        state = home / ".local" / "state" / "kaist-mail"
        state.mkdir(parents=True)
        _ = (state / "session.json").write_text(
            '{"version":1,"origin":"http://127.0.0.1:0","created_at":1,'
            + '"cookies":[{"name":"SESSION","value":"synthetic-session"}]}'
        )
        server, parts, unexpected = fixture_server()
        url = f"http://127.0.0.1:{server.server_port}"
        dooray = {"KAIST_MAIL_BASE_URL": url, "KAIST_MAIL_SSO_URL": f"{url}/"}
        try:
            folders = envelope("folders", extra=dooray)[0]["data"]
            if not any(f["name"] == "inbox" for f in folders):
                raise SystemExit("folders: no inbox")
            listed = json.loads((FIXTURES / "mails-list.json").read_bytes())
            rows = envelope("list", "--limit", "2", extra=dooray)[0]["data"]
            if [r["id"] for r in rows] != [
                m["id"] for m in listed["result"]["contents"][:2]
            ]:
                raise SystemExit("list --limit 2: wrong rows")
            message = envelope("read", MAIL_ID, extra=dooray)[0]["data"]
            if (message["subject"], message["marked_read"]) != (
                "[학사] 2026학년도 봄학기 수강신청 안내",
                True,
            ) or "안녕하세요, 학사팀입니다." not in message["body"]["text"]:
                raise SystemExit("read: wrong subject, body or marked_read")
            out = root / "다운로드"
            out.mkdir()
            saved = envelope("download", MAIL_ID, "--out", str(out), extra=dooray)[0][
                "data"
            ]
            if {
                f["part"]: Path(f["path"]).read_bytes() for f in saved["files"]
            } != parts:
                raise SystemExit(
                    "download: saved files differ from the served attachments"
                )
        finally:
            server.shutdown()
        if unexpected:
            raise SystemExit(f"unexpected requests: {unexpected}")
    print(
        f"Release smoke passed: kaist-mail {version}; checksum, install, CLI contract, folders/list/read/download"
    )


if __name__ == "__main__":
    main()
