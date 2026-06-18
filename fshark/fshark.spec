# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_data_files

fshark_dir = os.path.abspath('.')

a = Analysis(
    ['main.py'],
    pathex=[fshark_dir, os.path.join(fshark_dir, 'decoders')],
    binaries=[],
    datas=[
        (os.path.join(fshark_dir, 'cfg'), 'cfg'),
    ],
    hiddenimports=[
        'status',
        'pcap',
        'ethernet',
        'ip',
        'tcp',
        'udp',
        'sctp',
        's1ap',
        'ngap',
        'x2ap',
        'f1ap',
        'gtp',
        'gtpv2',
        'diameter',
        'sip',
        'http2',
        'sbi_dict',
        'm3ua',
        'megaco',
        'sgsap',
        'pfcp',
        'gb',
        'epcDNS',
        'lte_uu',
        'linuxcooked',
        'esp',
        'icmp',
        'rtp',
        'a11',
        'amr',
        'ldap',
        'check_ipv6',
        'CPLatency',
        'hpack',
    ],
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
    name='fshark',
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
