# -*- mode: python ; coding: utf-8 -*-
# VAULT.spec — PyInstaller specification file for reproducible onedir build

import os
import sys

block_cipher = None

a = Analysis(
    ['password_vault.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('vault.ico', '.'),
        ('version.py', '.'),
    ],
    hiddenimports=[
        'cryptography',
        'cryptography.hazmat.primitives.ciphers.aead',
        'argon2',
        'argon2.low_level',
        '_cffi_backend',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'unittest',
        'pytest',
        'tests_tier2',
        'tests_tier3',
        'tests_tier4',
        'pydoc',
        'doctest',
        'difflib',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher,
)

exe_kwargs = {
    'name': 'VAULT',
    'debug': False,
    'bootloader_ignore_signals': False,
    'strip': False,
    'upx': False,           # Explicitly disabled to avoid antivirus false positives
    'console': False,       # Windowed app (no command prompt window)
    'disable_windowed_traceback': False,
    'argv_emulation': False,
    'target_arch': None,
    'codesign_identity': None,
    'entitlements_file': None,
    'icon': 'vault.ico',
}

if os.path.exists('file_version_info.txt'):
    exe_kwargs['version'] = 'file_version_info.txt'

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    **exe_kwargs,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='VAULT',
)
