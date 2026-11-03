"""Run a real Uvicorn process on localhost with an isolated database, then cleanly stop it."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def serve(port: int) -> None:
    """Stop gracefully on parent stdin/EOF, including Windows venv launcher processes."""
    import uvicorn

    server = uvicorn.Server(
        uvicorn.Config(
            "app.main:create_app", factory=True, host="127.0.0.1", port=port, proxy_headers=False
        )
    )

    def wait_for_shutdown():
        sys.stdin.readline()
        server.should_exit = True

    threading.Thread(target=wait_for_shutdown, daemon=True).start()
    server.run()


def request(base: str, method: str, path: str, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    req = Request(
        base + path, data=body, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        response = urlopen(req, timeout=2)
    except HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def main() -> None:
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory() as directory:
        env = {
            **os.environ,
            "THREAT_DB_PATH": str(Path(directory) / "smoke.db"),
            "THREAT_API_KEY": "",
            "THREAT_RATE_LIMIT_REQUESTS": "100",
            "THREAT_MAX_BODY_BYTES": "65536",
        }
        with (Path(directory) / "uvicorn.log").open("w+", encoding="utf-8") as log:
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--serve",
                    str(port),
                ],
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            try:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("Uvicorn exited before becoming ready")
                    try:
                        status, body = request(base, "GET", "/health")
                        if status == 200:
                            break
                    except (URLError, TimeoutError):
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Uvicorn did not become ready within 15 seconds")
                    time.sleep(0.1)
                assert body == {"status": "ok"}
                payload = {"md5": MD5, "name": "Smoke.Test", "severity": "high"}
                assert request(base, "POST", "/info", payload)[0] == 201
                assert request(base, "POST", "/info", payload)[0] == 409
                status, body = request(base, "GET", f"/info/{MD5.upper()}")
                assert status == 200 and body["md5"] == MD5 and body["severity"] == "high"
                status, body = request(base, "PUT", f"/info/{MD5}", {"name": "Updated"})
                assert status == 200 and body["name"] == "Updated" and body["severity"] == "unknown"
                assert request(base, "GET", "/info/invalid")[0] == 400
                assert request(base, "GET", f"/info/{'0' * 32}")[0] == 404
                print("Real HTTP smoke test passed: health, create, read, replace, 400, 404, 409")
            except Exception:
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                try:
                    process.communicate(input="stop\n", timeout=10)
                except subprocess.TimeoutExpired:
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                            check=True,
                            capture_output=True,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                    else:
                        process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--serve":
        serve(int(sys.argv[2]))
    else:
        main()
