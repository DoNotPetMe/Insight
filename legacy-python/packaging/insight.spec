# PyInstaller spec — builds the standalone Insight desktop app.
#
#   pyinstaller packaging/insight.spec
#
# On Windows this produces dist/Insight/Insight.exe (a windowed app); the same
# spec works on Linux/macOS to produce a native bundle.

import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None
ROOT = os.path.abspath(os.getcwd())

hidden = (
    collect_submodules("capstone")
    + collect_submodules("UnityPy")
    + collect_submodules("PyMemoryEditor")
)

datas = [
    (os.path.join("insight", "web", "templates"), os.path.join("insight", "web", "templates")),
    (os.path.join("insight", "web", "static"), os.path.join("insight", "web", "static")),
]
# UnityPy ships data resources (type trees) it needs at runtime
try:
    datas += collect_data_files("UnityPy")
except Exception:
    pass

a = Analysis(
    [os.path.join("insight", "desktop", "__main__.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="Insight",
    debug=False,
    strip=False,
    upx=True,
    console=False,           # windowed GUI app
)
coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas,
    strip=False, upx=True, name="Insight",
)
