# PyInstaller spec for SessLint — onefile console executable.
#
# Build (from the repository root):
#   python -m PyInstaller packaging/sesslint.spec
# or via the orchestrator (recommended — handles naming, checksums, signing):
#   python scripts/package.py
#
# Produces dist/sesslint (Linux/macOS) or dist/sesslint.exe (Windows) unless
# --distpath overrides it. SessLint is a pure-standard-library project, so no
# hidden imports, excludes, or runtime hooks are needed beyond what PyInstaller's
# import analysis detects automatically.
#
# SPECPATH is injected by PyInstaller: the directory containing this spec file.

import os

REPO_ROOT = os.path.dirname(SPECPATH)  # packaging/ -> repository root
SRC_DIR = os.path.join(REPO_ROOT, "src")
ENTRY_SCRIPT = os.path.join(SRC_DIR, "sesslint", "__main__.py")

# Runtime schema lookup probes <sys.prefix>/share/sesslint/schemas/ (see e.g.
# src/sesslint/canonical.py::get_session_schema_path) — the same location the
# wheel installs them as shared data. Inside a frozen bundle sys.prefix is the
# PyInstaller application directory (sys._MEIPASS for onefile), so mirroring
# the shared-data layout here keeps the existing lookup working unmodified.
SCHEMAS_DIR = os.path.join(REPO_ROOT, "schemas")

a = Analysis(
    [ENTRY_SCRIPT],
    pathex=[SRC_DIR],
    binaries=[],
    datas=[(SCHEMAS_DIR, "share/sesslint/schemas")],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="sesslint",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # keep builds offline + reproducible; UPX requires a separate download
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
