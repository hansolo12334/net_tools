# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['test_qt_rebuild.py'],
    pathex=[],
    binaries=[],
    datas=[('build\\network_monitor_dll.dll', '.'), ('build\\wpcap.dll', '.'), ('build\\libgcc_s_seh-1.dll', '.'), ('build\\libstdc++-6.dll', '.'), ('build\\libwinpthread-1.dll', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='test_qt_rebuild',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
