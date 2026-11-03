"""Generate deterministic Pydantic v2 models from the checked-in OpenAPI contract."""

import argparse
import difflib
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "app" / "generated" / "models.py"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail when generated models are stale")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "models.py"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "datamodel_code_generator",
                "--input",
                "app/openapi.yaml",
                "--input-file-type",
                "openapi",
                "--output",
                str(output),
                "--output-model-type",
                "pydantic_v2.BaseModel",
                "--target-python-version",
                "3.12",
                "--disable-timestamp",
                "--formatters",
                "black",
                "isort",
                "--use-standard-collections",
                "--use-union-operator",
                "--strict-nullable",
                "--strict-types",
                "str",
                "int",
                "float",
                "bool",
                "bytes",
            ],
            cwd=ROOT,
            check=True,
        )
        generated = output.read_text(encoding="utf-8")
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != generated:
            print(
                "".join(
                    difflib.unified_diff(
                        current.splitlines(True),
                        generated.splitlines(True),
                        fromfile=str(TARGET),
                        tofile="regenerated models",
                    )
                )
            )
            return 1
        print("Generated models match app/openapi.yaml")
    else:
        TARGET.write_text(generated, encoding="utf-8", newline="\n")
        print(f"Generated {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
