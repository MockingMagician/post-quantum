#!/usr/bin/env python3
"""Build libFuzzer seeds from the checked-in public protocol fixture."""
import json
from pathlib import Path
root = Path(__file__).resolve().parent.parent
v = json.loads((root / 'validation/vectors/protocol-v1.json').read_text())
corpus = root / 'fuzz/corpus/byte_inputs'
corpus.mkdir(parents=True, exist_ok=True)
for field in ('encryptionPrivate', 'signingPrivate', 'encryptionPublic', 'signingPublic', 'envelope', 'signature'):
    prefix = 1 if field == 'envelope' else 2 if field == 'signature' else 0
    (corpus / field).write_bytes(bytes([prefix]) + bytes.fromhex(v[field]))
operations = root / 'fuzz/corpus/operations'
operations.mkdir(parents=True, exist_ok=True)
(operations / 'binary').write_bytes(bytes(range(256)))
(operations / 'empty').write_bytes(b'')
print('Seeded fuzz corpora from protocol v1 vector')
primitives = root / 'fuzz/corpus/primitives'
primitives.mkdir(parents=True, exist_ok=True)
for size in (0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 135, 136, 137, 167, 168, 169, 256, 1024, 4096):
    (primitives / f'boundary-{size}').write_bytes(bytes(i % 256 for i in range(size)))
print('Seeded primitive boundaries through 4096 bytes')
