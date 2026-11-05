"""Package an explicit tracked source set and a tested Windows bundle."""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_log_analyzer import __version__
from security_log_analyzer.core import create_case, import_file, analyze, load_indicators
from security_log_analyzer.reports import export_report


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--app-dir',required=True)
    parser.add_argument('--output',default='dist')
    parser.add_argument('--tag',required=True)
    args=parser.parse_args()
    if args.tag != 'v'+__version__:
        parser.error('Tag must match the application version')
    output=Path(args.output).resolve()
    output.mkdir(parents=True,exist_ok=True)
    app=Path(args.app_dir).resolve()
    for name in ('SecurityLogAnalyzer.exe','security-log-analyzer-cli.exe','_internal/python313.dll'):
        if not (app/name).is_file():
            parser.error('Missing bundle member: '+name)
    names=[n for n in subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0') if n]
    if any(n.startswith(('work/','cases/','data/')) or n=='memory.md' or n.endswith(('.sqlite','.evtx','.etl')) for n in names):
        parser.error('Unexpected private/runtime data in tracked source files')
    source=output/f'Security-Log-Analyzer-{args.tag}-source.zip'
    windows=output/f'Security-Log-Analyzer-{args.tag}-windows-x64.zip'
    with zipfile.ZipFile(source,'w',zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.write(ROOT/name,'security-log-analyzer/'+name)
    with zipfile.ZipFile(windows,'w',zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(app.rglob('*')):
            if file.is_file():
                archive.write(file,'SecurityLogAnalyzer/'+file.relative_to(app).as_posix())
        for name in names:
            if name.startswith(('samples/','docs/','packaging/licenses/')) or name in ('README.md','LICENSE','CHANGELOG.md','SECURITY.md','THIRD-PARTY-NOTICES.md'):
                target=name.replace('packaging/licenses/','licenses/')
                archive.write(ROOT/name,'SecurityLogAnalyzer/'+target)
        archive.writestr('SecurityLogAnalyzer/START-HERE.txt',
            'Security Log Analyzer '+__version__+'\n\nExtract the complete ZIP. Run SecurityLogAnalyzer.exe.\n'
            'No Python installation is required. Keep _internal beside the executables.\n'
            'Command line: security-log-analyzer-cli.exe --help\n'
            'Create case databases in a local folder you control, outside this application folder.\n'
            'Only synthetic samples are included. Binaries are unsigned.\n')
    with tempfile.TemporaryDirectory() as temp:
        case=Path(temp)/'demo.sqlite'
        create_case(case)
        for name in ('appliance-demo.cef','appliance-demo.leef','iis-demo.log','nested-demo.json'):
            import_file(case,ROOT/'samples'/name)
        indicators=load_indicators(ROOT/'samples/indicators.txt')
        export_report(case,output/'Security-Log-Analyzer-demo-report.html',analyze(case,indicators,failure_threshold=3),
                      {'failure_threshold':3,'fanout_threshold':20,'indicators':[str(n) for n in indicators],'synthetic_demo':True})
    assets=[source,windows,output/'Security-Log-Analyzer-demo-report.html']
    for file in (source,windows):
        with zipfile.ZipFile(file) as archive:
            if archive.testzip() is not None:
                raise ValueError('Archive integrity check failed')
    sums=''.join(hashlib.sha256(file.read_bytes()).hexdigest()+'  '+file.name+'\n' for file in assets)
    (output/'SHA256SUMS.txt').write_text(sums,encoding='utf-8')
    print(json.dumps({file.name:file.stat().st_size for file in [*assets,output/'SHA256SUMS.txt']},indent=2))


if __name__=='__main__':
    main()
