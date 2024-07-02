# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['zte.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('config.ini', '.'),  # Ensure this path is correct
    ],
    hiddenimports=[
        'ttkbootstrap',  # Ensure this import is correct
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher,
)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='zte',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Change to True to see console output
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='zte',
)
