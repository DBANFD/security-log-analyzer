"""Entry point shared by the desktop and console Windows bundles."""
import sys
from pathlib import Path

if Path(sys.executable).stem.lower().endswith('-cli'):
    from security_log_analyzer.__main__ import main
    main()
else:
    try:
        from security_log_analyzer.gui import run
        args = sys.argv[1:]
        if args and (len(args) != 2 or args[0] != '--case'):
            raise ValueError('Usage: SecurityLogAnalyzer.exe [--case path.sqlite]')
        run(args[1] if args else None)
    except Exception as exc:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, str(exc), 'Security Log Analyzer could not start', 0x10)
        raise SystemExit(1)
