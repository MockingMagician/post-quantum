#!/usr/bin/env python3
"""Independent OpenSSL <-> Rust <-> Node protocol tests. Test seeds are public."""
import argparse
import hashlib
import hmac
import json
import os
import subprocess
from pathlib import Path
from openssl_backend import Key, aead, version

ROOT = Path(__file__).resolve().parent.parent
VECTOR = ROOT / 'validation/vectors/protocol-v1.json'


def header(kind, size):
    return b'PQRS' + bytes([1, kind]) + size.to_bytes(4, 'little')


def exported(kind, payload):
    return header(kind, len(payload)) + payload


def derive(shared, public, prefix):
    # RFC5869 extract + first SHA-512 expand block (32-byte output).
    prk = hmac.digest(b'post-quantum/encryption/v1', shared, 'sha512')
    info = prefix[:10] + public + prefix[10:]
    return hmac.digest(prk, info + b'\x01', 'sha512')[:32]


def transcript(message, context):
    return header(32, 4627) + len(context).to_bytes(2, 'little') + context + message


def encrypt(public, message, aad):
    kem = Key('ML-KEM-1024', public=public)
    try:
        ct, ss = kem.encapsulate()
    finally:
        kem.close()
    nonce = os.urandom(12)
    prefix = header(16, 1568 + 12 + len(message) + 16) + ct + nonce
    key = derive(ss, public, prefix)
    return prefix + aead(key, nonce, message, prefix + len(aad).to_bytes(8, 'little') + aad, True)


def decrypt(seed, envelope, aad):
    assert envelope[:6] == b'PQRS\x01\x10'
    assert int.from_bytes(envelope[6:10], 'little') == len(envelope) - 10
    key = Key('ML-KEM-1024', seed=seed)
    try:
        prefix = envelope[:1590]
        secret = key.decapsulate(envelope[10:1578])
        derived = derive(secret, key.public(), prefix)
        return aead(derived, envelope[1578:1590], envelope[1590:],
                    prefix + len(aad).to_bytes(8, 'little') + aad, False)
    finally:
        key.close()


def produce(case):
    seed = bytes.fromhex(case['encryptionPrivate'])[10:]
    signing_seed = bytes.fromhex(case['signingPrivate'])[10:]
    message, aad, context = (bytes.fromhex(case[n]) for n in ('message', 'aad', 'context'))
    ek, sk = Key('ML-KEM-1024', seed=seed), Key('ML-DSA-87', seed=signing_seed)
    try:
        return dict(encryptionPublic=exported(1, ek.public()).hex(),
                    signingPublic=exported(3, sk.public()).hex(),
                    envelope=encrypt(ek.public(), message, aad).hex(),
                    signature=exported(32, sk.sign(transcript(message, context), b'post-quantum/signature/v1')).hex())
    finally:
        ek.close()
        sk.close()


def consume(case):
    message, aad, context = (bytes.fromhex(case[n]) for n in ('message', 'aad', 'context'))
    assert decrypt(bytes.fromhex(case['encryptionPrivate'])[10:], bytes.fromhex(case['envelope']), aad) == message
    sig = bytes.fromhex(case['signature'])
    assert sig[:10] == header(32, 4627)
    key = Key('ML-DSA-87', public=bytes.fromhex(case['signingPublic'])[10:])
    try:
        assert key.verify(transcript(message, context), sig[10:], b'post-quantum/signature/v1')
        assert not key.verify(transcript(message + b'!', context), sig[10:], b'post-quantum/signature/v1')
        assert not key.verify(transcript(message, context + b'!'), sig[10:], b'post-quantum/signature/v1')
    finally:
        key.close()
    damaged = bytes.fromhex(case['envelope'])
    damaged = damaged[:-1] + bytes([damaged[-1] ^ 1])
    try:
        decrypt(bytes.fromhex(case['encryptionPrivate'])[10:], damaged, aad)
    except RuntimeError:
        pass
    else:
        raise AssertionError('OpenSSL accepted altered AEAD tag')


def bridge(command, case, op):
    request = dict(case, op=op)
    payload = ''.join(f'{key}={value}\n' for key, value in request.items()) if Path(command[0]).name in ('interop', 'interop.exe') else json.dumps(request)
    result = subprocess.run(command, cwd=ROOT, input=payload,
                            text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', action='store_true', help='also require built native Node package')
    parser.add_argument('--write-vector', action='store_true', help='replace fixed public test fixture')
    args = parser.parse_args()
    if args.write_vector:
        case = {'description': 'Public test keys only. OpenSSL-created v1 interoperability vector.',
                'producer': version, 'message': '0001706f73742d7175616e74756dff',
                'aad': '746573742d61616400ff', 'context': '617574686f7200ff',
                'encryptionPrivate': exported(2, bytes(range(64))).hex(),
                'signingPrivate': exported(4, bytes(range(32))).hex()}
        case.update(produce(case))
        VECTOR.write_text(json.dumps(case, indent=2) + '\n')
    case = json.loads(VECTOR.read_text())
    consume(case)
    # Empty, short non-UTF8 and 64 KiB cases; limits are tested separately.
    bridges = [('Rust', [str(ROOT / 'target/debug/examples/interop')])]
    if args.node:
        bridges.append(('Node', ['node', 'validation/node_bridge.cjs']))
    scenarios = [(case['message'], case['aad'], case['context']), ('', '', ''),
                 ((bytes(range(256)) * 256).hex(), '00ff', ('ff' * 255))]
    exchanges = 0
    for msg, aad, context in scenarios:
        current = dict(case, message=msg, aad=aad, context=context)
        openssl_output = produce(current)
        current.update(openssl_output)
        for name, command in bridges:
            checked = bridge(command, current, 'consume')
            assert checked == {'plaintext': msg, 'valid': True}, name
            output = bridge(command, current, 'produce')
            assert output['encryptionPublic'] == current['encryptionPublic']
            assert output['signingPublic'] == current['signingPublic']
            consume(dict(current, **output))
            exchanges += 2
            for peer, peer_command in bridges:
                if peer != name:
                    assert bridge(peer_command, dict(current, **output), 'consume') == {'plaintext': msg, 'valid': True}
                    exchanges += 1
        print(f"PASS independent exchanges for message={len(bytes.fromhex(msg))}, context={len(bytes.fromhex(context))}")
    # Every bridge must also consume the immutable checked-in wire vector.
    for name, command in bridges:
        assert bridge(command, case, 'consume') == {'plaintext': case['message'], 'valid': True}, name
    print(json.dumps({'openssl': version, 'exchanges': exchanges,
                      'vectorSha256': hashlib.sha256(VECTOR.read_bytes()).hexdigest(), 'passed': True}))


if __name__ == '__main__':
    main()
