#!/usr/bin/env python3
"""Reproduce dependency-free Rust test fixtures from pinned source JSON (offline)."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def render(records):
    return ''.join(''.join(f'{key}={value}\n' for key, value in sorted(record.items())) + '\n' for record in records)

def outputs():
    for source in sorted((ROOT / 'acvp').glob('ML-*.json')):
        document = json.loads(source.read_text())
        records = []
        for group in document['testGroups']:
            metadata = {k: v for k, v in group.items() if k != 'tests'}
            for case in group['tests']:
                record = dict(metadata, **case)
                record = {k: str(v).lower() if isinstance(v, bool) else str(v) for k,v in record.items()}
                records.append(record)
        yield ROOT / 'kat' / (source.stem + '.kat'), render(records)
    vector = json.loads((ROOT / 'vectors/protocol-v1.json').read_text())
    yield ROOT / 'kat/protocol-v1.kat', render([{k:v for k,v in vector.items() if k not in ('description','producer')}])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for path, content in outputs():
        if args.check:
            if path.read_text() != content:
                raise SystemExit(f'Fixture conversion mismatch: {path}')
        else:
            path.write_text(content)
    print('Verified' if args.check else 'Prepared', '195 ACVP cases and immutable protocol fixture for std-only tests')

if __name__ == '__main__': main()
