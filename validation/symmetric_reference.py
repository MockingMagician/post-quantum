#!/usr/bin/env python3
"""Reproduce test-only Poly1305/PQRS-AEAD reference cases without package code.

Poly1305 uses Python arbitrary-precision integers and the mathematical definition
in RFC 8439 section 2.5, independently of the production limb implementation.
ChaCha20-Poly1305 outputs come from OpenSSL through openssl_backend.py. Inputs
are deterministic PUBLIC fixtures, not entropy suitable for production keys.
Default/--check compares the committed corpus; --write deliberately replaces it.
"""
import hashlib
import json
import sys
from pathlib import Path
from openssl_backend import aead, version

DIRECTORY = Path(__file__).resolve().parent / 'kat'
DESTINATION = DIRECTORY / 'symmetric-independent.kat'
MANIFEST = DIRECTORY / 'symmetric-independent-manifest.json'


def stream(case, label, size):
    domain = b'post-quantum:public-symmetric-fixture:v1\0'
    return hashlib.shake_256(domain + case.to_bytes(4, 'little') + label).digest(size)


def poly_reference(key, message):
    r = int.from_bytes(key[:16], 'little') & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    accumulator = 0
    for offset in range(0, len(message), 16):
        block = int.from_bytes(message[offset:offset + 16] + b'\x01', 'little')
        accumulator = ((accumulator + block) * r) % ((1 << 130) - 5)
    return ((accumulator + int.from_bytes(key[16:], 'little')) % (1 << 128)).to_bytes(16, 'little')


def corpus():
    records = []
    boundaries = list(range(34)) + [63, 64, 65, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 4095, 4096]
    for case in range(256):
        length = boundaries[case] if case < len(boundaries) else int.from_bytes(stream(case, b'length', 2), 'little') % 4097
        key = stream(case, b'key', 32)
        message = stream(case, b'message', length)
        if case % 7 == 0:
            key = bytes([0xFF]) * 32
            message = bytes([0xFF]) * length
        elif case % 7 == 1:
            key = bytes(16) + key[16:]
        elif case % 7 == 2:
            key = key[:16] + bytes(16)
        elif case % 7 == 3:
            message = bytes(length)
        records.append(dict(kind='poly1305', case=str(case), key=key.hex(), message=message.hex(),
                            expected=poly_reference(key, message).hex()))
    for case in range(128):
        length = boundaries[case % len(boundaries)]
        aad_length = boundaries[(case * 7) % len(boundaries)]
        key, nonce = stream(case, b'aead-key', 32), stream(case, b'nonce', 12)
        message, aad = stream(case, b'aead-message', length), stream(case, b'aad', aad_length)
        expected = aead(key, nonce, message, aad, True)
        assert aead(key, nonce, expected, aad, False) == message
        records.append(dict(kind='aead', case=str(case), key=key.hex(), nonce=nonce.hex(),
                            message=message.hex(), aad=aad.hex(), expected=expected.hex()))
    return ''.join('\n'.join(f'{key}={value}' for key, value in case.items()) + '\n\n' for case in records).encode()


def main():
    if sys.argv[1:] not in ([], ['--check'], ['--write']):
        raise SystemExit('Usage: python3 validation/symmetric_reference.py [--check | --write]')
    data = corpus()
    digest = hashlib.sha256(data).hexdigest()
    if sys.argv[1:] == ['--write']:
        DESTINATION.write_bytes(data)
        MANIFEST.write_text(json.dumps(dict(schemaVersion=1, sha256=digest,
            publicTestData=True, poly1305Cases=256, aeadCases=128,
            poly1305Reference='Independent Python integer arithmetic, RFC 8439 section 2.5',
            aeadReference=version, generator='validation/symmetric_reference.py'), indent=2) + '\n')
    else:
        if DESTINATION.read_bytes() != data or json.loads(MANIFEST.read_text())['sha256'] != digest:
            raise SystemExit('Independent symmetric fixtures differ from their frozen references')
    print(f'Independent symmetric cases: 256 Poly1305 + 128 AEAD; {version}; sha256={digest}')


if __name__ == '__main__':
    main()
