#!/usr/bin/env python3
"""Reproduce the checked-in NIST subset; the manifest pins upstream SHA-256s."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

COMMIT = '975de31eb83d87039ec88934fdc47d8c312b892d'
BASE = f'https://raw.githubusercontent.com/usnistgov/ACVP-Server/{COMMIT}/gen-val/json-files/'
MODES = ('ML-KEM-keyGen-FIPS203', 'ML-KEM-encapDecap-FIPS203',
         'ML-DSA-keyGen-FIPS204', 'ML-DSA-sigGen-FIPS204', 'ML-DSA-sigVer-FIPS204')
ROOT = Path(__file__).resolve().parent / 'acvp'


def selected(group):
    return (group['parameterSet'] in ('ML-KEM-1024', 'ML-DSA-87')
            and not group.get('externalMu', False)
            and group.get('preHash') != 'preHash')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='verify local hashes only (offline)')
    args = parser.parse_args()
    manifest_path = ROOT / 'manifest.json'
    if args.check:
        manifest = json.loads(manifest_path.read_text())
        for item in manifest['files']:
            data = (ROOT / item['file']).read_bytes()
            assert hashlib.sha256(data).hexdigest() == item['sha256'], item['file']
        print(f"Verified {len(manifest['files'])} pinned ACVP fixture hashes")
        return
    existing = json.loads(manifest_path.read_text()) if manifest_path.exists() else None
    files = []
    for mode in MODES:
        url = BASE + mode + '/internalProjection.json'
        raw = urlopen(url, timeout=60).read()
        source_hash = hashlib.sha256(raw).hexdigest()
        if existing:
            record = next(x for x in existing['files'] if x['file'] == mode + '.json')
            assert source_hash == record['upstreamSha256'], 'upstream content changed'
        data = json.loads(raw)
        data['testGroups'] = [g for g in data['testGroups'] if selected(g)]
        encoded = (json.dumps(data, indent=2) + '\n').encode()
        output = ROOT / (mode + '.json')
        output.write_bytes(encoded)
        files.append({'file': output.name, 'sha256': hashlib.sha256(encoded).hexdigest(),
                      'upstream': url, 'upstreamSha256': source_hash,
                      'groups': [g['tgId'] for g in data['testGroups']],
                      'testCases': sum(len(g['tests']) for g in data['testGroups'])})
    manifest = {'repository': 'https://github.com/usnistgov/ACVP-Server', 'commit': COMMIT,
                'selection': 'All category-5 groups except ML-DSA preHash and externalMu; no individual test cases removed.',
                'files': files}
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    print('Wrote', sum(f['testCases'] for f in files), 'official test cases')


if __name__ == '__main__':
    main()
