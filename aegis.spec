# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

block_cipher = None

sklearn_datas, sklearn_binaries, sklearn_hiddenimports = collect_all('sklearn')
scapy_datas, scapy_binaries, scapy_hiddenimports = collect_all('scapy')

a = Analysis(
    ['frontend/app.py'],
    pathex=[],
    binaries=sklearn_binaries + scapy_binaries,
    datas=[
        ('models/aegis_ciciomt_model.onnx', 'models'),  # Updated to ciciomt model
        ('aegisicon.png', '.'),
        ('backend', 'backend'),
    ] + sklearn_datas + scapy_datas,
    hiddenimports=[
        'customtkinter',
        'joblib',
        'sklearn',
        'sklearn.ensemble',
        'sklearn.ensemble._forest',
        'sklearn.tree',
        'sklearn.utils._typedefs',
        'pandas',
        'scapy',
    ] + sklearn_hiddenimports + scapy_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AEGIS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

app = BUNDLE(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='AEGIS.app',
    icon='aegisicon.icns',
    bundle_identifier=None,
)