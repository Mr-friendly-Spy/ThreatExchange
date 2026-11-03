"""Verify a running deployment over HTTP/TLS; creates one uniquely identified test record."""

import argparse
import json
import os
import socket
import ssl
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def call(base, method, path, payload=None, *, context=None, key=None):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["X-API-Key"] = key
    body = json.dumps(payload).encode() if payload is not None else None
    req = Request(base + path, data=body, method=method, headers=headers)
    try:
        response = urlopen(req, context=context, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def verify_tls(base: str, ca_file: Path) -> ssl.SSLContext:
    """Require trusted chain, valid hostname and TLS 1.2+, with negative checks."""
    address = urlsplit(base)
    host, port = address.hostname, address.port or 443
    context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with (
        socket.create_connection((host, port), timeout=5) as raw,
        context.wrap_socket(raw, server_hostname=host) as connection,
    ):
        assert connection.version() in {"TLSv1.2", "TLSv1.3"}
        certificate = connection.getpeercert()
        print(f"Verified {connection.version()}, certificate expires {certificate['notAfter']}")

    # An empty trust store must reject our local CA. Never disable certificate checking.
    untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        with (
            socket.create_connection((host, port), timeout=5) as raw,
            untrusted.wrap_socket(raw, server_hostname=host),
        ):
            raise AssertionError("Untrusted certificate was accepted")
    except ssl.SSLCertVerificationError:
        pass

    # The proxy must refuse a hostname for which it cannot provide a valid certificate.
    try:
        with (
            socket.create_connection((host, port), timeout=5) as raw,
            context.wrap_socket(raw, server_hostname="wrong-host.invalid"),
        ):
            raise AssertionError("An unrelated TLS server name was accepted")
    except ssl.SSLError:
        pass
    print("Negative TLS checks passed: unknown CA and incorrect hostname rejected")
    return context


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--record-file", type=Path, help="Save test MD5 for restart verification")
    parser.add_argument(
        "--read-record", type=Path, help="Only read the previously created test record"
    )
    args = parser.parse_args()
    key = os.environ.get("THREAT_API_KEY")
    if key is None:
        # Read the local development key without printing it or placing it in argv.
        from dotenv import dotenv_values

        key = dotenv_values(Path(__file__).resolve().parents[1] / ".env").get("THREAT_API_KEY")
    context = ssl.create_default_context(cafile=str(args.ca_file)) if args.ca_file else None

    deadline = time.monotonic() + 30
    while True:
        try:
            if call(args.base_url, "GET", "/health", context=context)[0] == 200:
                break
        except (URLError, TimeoutError, ConnectionError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError("Deployment did not become ready within 30 seconds")
        time.sleep(0.2)
    if args.base_url.startswith("https://"):
        if args.ca_file is None:
            parser.error("HTTPS verification requires --ca-file")
        context = verify_tls(args.base_url, args.ca_file)

    def request(method, path, payload=None, *, authenticate=True):
        return call(
            args.base_url, method, path, payload, context=context, key=key if authenticate else None
        )

    if args.read_record:
        md5 = args.read_record.read_text(encoding="utf-8").strip()
        status, body = request("GET", f"/info/{md5}")
        assert status == 200 and body["name"] == "Deployment.Check.Updated"
        print("Persisted record survived container recreation")
        return

    md5 = uuid.uuid4().hex
    payload = {"md5": md5, "name": "Deployment.Check", "severity": "high"}
    if key:
        assert request("GET", f"/info/{md5}", authenticate=False)[0] == 401
    assert request("POST", "/info", payload)[0] == 201
    assert request("POST", "/info", payload)[0] == 409
    status, body = request("GET", f"/info/{md5.upper()}")
    assert status == 200 and body["md5"] == md5 and body["severity"] == "high"
    status, body = request("PUT", f"/info/{md5}", {"name": "Deployment.Check.Updated"})
    assert status == 200 and body["severity"] == "unknown"
    assert request("GET", "/info/invalid")[0] == 400
    assert request("GET", f"/info/{'0' * 32}")[0] == 404
    if args.record_file:
        args.record_file.write_text(md5, encoding="utf-8")
    print("Deployment checks passed: health, create/read/replace, 400/404/409 and API key")


if __name__ == "__main__":
    main()
