# PyInstaller spec for the PwnBroker Windows agent.
#
# Builds a --onedir bundle (not --onefile): this binary is meant to be
# launched by the Windows Service Control Manager and auto-restarted on
# crash (see the installer's failure-action config), so it should start
# instantly and not pay onefile's self-extract-to-temp cost on every
# restart. onedir keeps agent.exe next to its DLLs on disk, which is also
# the more predictable layout for a process the SCM starts outside any
# user session.
#
# Run from the repo root:
#   pyinstaller installer/windows/pwnbroker_agent.spec
# Output: dist/pwnbroker_agent/pwnbroker_agent.exe (+ deps alongside it)

# -*- mode: python ; coding: utf-8 -*-
import os

# SPECPATH is injected by PyInstaller into the spec file's exec namespace —
# the absolute directory containing *this* file. Using it (rather than a
# bare relative path) means the build works regardless of the working
# directory `pyinstaller` is invoked from.
_AGENT_SRC = os.path.join(SPECPATH, '..', '..', 'app', 'static', 'agent', 'pwnbroker_agent.py')

a = Analysis(
    [_AGENT_SRC],
    pathex=[],
    binaries=[],
    datas=[],
    # win32timezone is imported lazily by pywin32's service framework at
    # runtime (not a top-level import in agent.py), so PyInstaller's static
    # analysis won't find it on its own — without this it fails only when
    # the SCM actually starts the service, not during a `debug` test run.
    hiddenimports=['win32timezone'],
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
    [],
    exclude_binaries=True,
    name='pwnbroker_agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name='pwnbroker_agent',
)
