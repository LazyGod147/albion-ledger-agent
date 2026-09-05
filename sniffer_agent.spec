# PyInstaller spec — собирает снифер в один albion-ledger-agent.exe
#
# Локально (на Windows):
#   pip install -r requirements.txt pyinstaller
#   pyinstaller --clean --noconfirm sniffer_agent.spec
# Результат — dist/albion-ledger-agent.exe
#
# В облаке этим же файлом пользуется GitHub Actions — см.
# .github/workflows/build-agent.yml. Ничего править не нужно.

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

hiddenimports = []
hiddenimports += collect_submodules('scapy')
hiddenimports += collect_submodules('photon_packet_parser')
hiddenimports += collect_submodules('pystray')

datas = collect_data_files('scapy')

a = Analysis(
    ['sniffer_agent.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # тяжёлые пакеты, которые тянутся транзитом, но не нужны агенту
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'IPython'],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='albion-ledger-agent',
    debug=False,
    strip=False,
    upx=False,          # UPX часто ложно срабатывает у антивирусов — не жмём
    console=True,       # агент показывает лог в консоли
    disable_windowed_traceback=False,
)
