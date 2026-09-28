"""T-12: schema resources in a checkout, installed wheel or frozen executable."""

import sys
from pathlib import Path


def schema_path(name: str, development_path: Path) -> Path:
    """Resolve shared schema data without depending on the working directory."""
    bundle = getattr(sys, "_MEIPASS", None)
    if isinstance(bundle, str):
        frozen_path = Path(bundle) / "share" / "sesslint" / "schemas" / name
        if frozen_path.is_file():
            return frozen_path
    if development_path.is_file():
        return development_path
    installed = Path(sys.prefix) / "share" / "sesslint" / "schemas" / name
    return installed if installed.is_file() else development_path
