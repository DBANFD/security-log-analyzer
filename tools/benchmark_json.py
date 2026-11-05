"""Generate and import a nested JSON array without building it in memory."""
import argparse
import json
import time
from pathlib import Path
from benchmark import peak_memory_mb  # Also makes the repository importable.
from security_log_analyzer.core import create_case, import_file, summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--count', type=int, default=100000)
    parser.add_argument('--folder', default='work/json-benchmark')
    args = parser.parse_args()
    folder = Path(args.folder)
    folder.mkdir(parents=True, exist_ok=True)
    case = folder / 'case.sqlite'
    source = folder / 'nested.json'
    if case.exists() or source.exists():
        parser.error('Choose a fresh benchmark folder')
    with source.open('w', encoding='utf-8') as f:
        f.write('{"metadata":{"synthetic":true},"data":{"events":[')
        for i in range(args.count):
            if i:
                f.write(',')
            f.write(json.dumps({'@timestamp':'2026-01-15T10:00:00Z','host':{'name':f'demo-{i%16}'},'source':{'ip':f'10.0.0.{i%200+1}'},'destination':{'ip':'192.0.2.10'},'message':f'Synthetic nested event {i}','event':{'action':'ConnectionSuccess'}},separators=(',',':')))
        f.write(']}}')
    create_case(case)
    start = time.perf_counter()
    result = import_file(case, source)
    elapsed = time.perf_counter() - start
    assert result['records'] == args.count
    assert summary(case)['events'] == args.count
    result.update(source_mib=round(source.stat().st_size/1024**2,1), database_mib=round(case.stat().st_size/1024**2,1), import_seconds=round(elapsed,2), peak_process_working_set_mib=peak_memory_mb())
    (folder/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
