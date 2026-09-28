"""Package execution entry point for python -m sesslint."""

from __future__ import annotations

import sys

if __name__ == "__main__":
    if getattr(sys, "frozen", False):
        # T-14: PyInstaller workers reuse this executable. Dispatch their
        # internal arguments before CLI parsing, on every frozen platform.
        # Keep the import lazy so ordinary offline CLI/API imports stay lean.
        from multiprocessing import freeze_support

        freeze_support()

    from sesslint.cli import main

    raise SystemExit(main())
