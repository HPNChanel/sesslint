#!/usr/bin/env python3
"""T-12: portable reproducible man-page archive builder (no platform tar dependency)."""

import argparse
import gzip
import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def build(target: Path, epoch: int) -> None:
    generator = Path(__file__).resolve().with_name("gen_man.py")
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        subprocess.run([sys.executable, str(generator), "--out", str(root)], check=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        with (
            target.open("xb") as output,
            gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch) as compressed,
            tarfile.open(fileobj=compressed, mode="w") as archive,
        ):
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    data = path.read_bytes()
                    info = tarfile.TarInfo("man/" + path.relative_to(root).as_posix())
                    info.size, info.mtime, info.mode = len(data), epoch, 0o644
                    archive.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    build(args.output, args.epoch)
