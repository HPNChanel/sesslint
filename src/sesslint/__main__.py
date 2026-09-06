"""Package execution entry point for python -m sesslint."""

from __future__ import annotations

from sesslint.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
