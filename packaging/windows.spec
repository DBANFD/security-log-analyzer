# Build both entry points against the same one-folder dependency bundle.
from pathlib import Path
root = Path(SPECPATH).parent
a = Analysis([str(root / 'tools' / 'frozen_entry.py')], pathex=[str(root)],
             binaries=[], datas=[], hiddenimports=[], hookspath=[],
             hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name='SecurityLogAnalyzer',
          debug=False, strip=False, upx=False, console=False)
cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name='security-log-analyzer-cli',
          debug=False, strip=False, upx=False, console=True)
app = COLLECT(gui, cli, a.binaries, a.datas, strip=False, upx=False, name='SecurityLogAnalyzer')
