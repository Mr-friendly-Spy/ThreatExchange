"""Export only the public HTTPS CA certificate from the running Compose deployment."""

import argparse
import os
import shutil
import ssl
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-name", default="threat-exchange")
    parser.add_argument("--output", type=Path, default=ROOT / "certs" / "local-ca.crt")
    args = parser.parse_args()
    command = ["docker"]
    if os.name == "nt" and shutil.which("docker") is None:
        command = ["wsl", "-d", "Ubuntu", "-u", "root", "--cd", str(ROOT), "--", "docker"]
    command += [
        "compose",
        "--project-name",
        args.project_name,
        "-f",
        "compose.yaml",
        "-f",
        "compose.https.yaml",
        "exec",
        "-T",
        "proxy",
        "cat",
        "/data/caddy/pki/authorities/local/root.crt",
    ]
    deadline = time.monotonic() + 20
    while True:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, check=False)
        if result.returncode == 0:
            certificate = result.stdout
            break
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Cannot export CA: {result.stderr.decode(errors='replace')}")
        time.sleep(0.5)
    ssl.PEM_cert_to_DER_cert(certificate.decode("ascii"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(certificate)
    print(f"Exported public CA to {args.output}. System trust stores were not changed.")


if __name__ == "__main__":
    main()
