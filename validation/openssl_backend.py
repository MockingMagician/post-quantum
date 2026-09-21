"""Test-only independent OpenSSL >=3.5 binding; never used by the package.

Only public libcrypto APIs are used. Override OPENSSL_LIBCRYPTO if the system
library is older than the openssl executable. Python secrets are not zeroized.
"""
import ctypes as C
import ctypes.util
import os
from pathlib import Path


class Param(C.Structure):
    _fields_ = [('key', C.c_char_p), ('data_type', C.c_uint), ('data', C.c_void_p),
                ('data_size', C.c_size_t), ('return_size', C.c_size_t)]


def load_crypto():
    explicit = os.environ.get('OPENSSL_LIBCRYPTO')
    candidates = [explicit] if explicit else [ctypes.util.find_library('crypto'),
                  '/home/linuxbrew/.linuxbrew/opt/openssl@3/lib/libcrypto.so.3',
                  '/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib']
    for path in filter(None, candidates):
        try:
            lib = C.CDLL(path)
            lib.OpenSSL_version_num.restype = C.c_ulong
            if lib.OpenSSL_version_num() >= 0x30500000:
                return lib
        except OSError:
            if explicit:
                raise RuntimeError('Cannot load explicitly selected OPENSSL_LIBCRYPTO') from None
    raise RuntimeError('Independent tests require libcrypto >=3.5; set OPENSSL_LIBCRYPTO')


lib = load_crypto()
P, S, I = C.c_void_p, C.c_size_t, C.c_int

def bind(name, result, *args):
    fn = getattr(lib, name)
    fn.restype, fn.argtypes = result, list(args)
    return fn

version = bind('OpenSSL_version', C.c_char_p, I)(0).decode()
ctx_new = bind('EVP_PKEY_CTX_new_from_name', P, P, C.c_char_p, C.c_char_p)
ctx_key = bind('EVP_PKEY_CTX_new_from_pkey', P, P, P, C.c_char_p)
ctx_free = bind('EVP_PKEY_CTX_free', None, P)
key_free = bind('EVP_PKEY_free', None, P)
from_init = bind('EVP_PKEY_fromdata_init', I, P)
fromdata = bind('EVP_PKEY_fromdata', I, P, C.POINTER(P), I, C.POINTER(Param))
get_octets = bind('EVP_PKEY_get_octet_string_param', I, P, C.c_char_p, P, S, C.POINTER(S))
enc_init = bind('EVP_PKEY_encapsulate_init', I, P, C.POINTER(Param))
enc = bind('EVP_PKEY_encapsulate', I, P, P, C.POINTER(S), P, C.POINTER(S))
dec_init = bind('EVP_PKEY_decapsulate_init', I, P, C.POINTER(Param))
dec = bind('EVP_PKEY_decapsulate', I, P, P, C.POINTER(S), P, S)
md_new = bind('EVP_MD_CTX_new', P)
md_free = bind('EVP_MD_CTX_free', None, P)
sign_init = bind('EVP_DigestSignInit_ex', I, P, P, C.c_char_p, P, C.c_char_p, P, C.POINTER(Param))
verify_init = bind('EVP_DigestVerifyInit_ex', I, P, P, C.c_char_p, P, C.c_char_p, P, C.POINTER(Param))
sign = bind('EVP_DigestSign', I, P, P, C.POINTER(S), P, S)
verify = bind('EVP_DigestVerify', I, P, P, S, P, S)
cipher_new = bind('EVP_CIPHER_CTX_new', P)
cipher_free = bind('EVP_CIPHER_CTX_free', None, P)
chacha = bind('EVP_chacha20_poly1305', P)
einit = bind('EVP_EncryptInit_ex', I, P, P, P, P, P)
dinit = bind('EVP_DecryptInit_ex', I, P, P, P, P, P)
eupdate = bind('EVP_EncryptUpdate', I, P, P, C.POINTER(I), P, I)
dupdate = bind('EVP_DecryptUpdate', I, P, P, C.POINTER(I), P, I)
efinal = bind('EVP_EncryptFinal_ex', I, P, P, C.POINTER(I))
dfinal = bind('EVP_DecryptFinal_ex', I, P, P, C.POINTER(I))
ctrl = bind('EVP_CIPHER_CTX_ctrl', I, P, I, I, P)


def check(result):
    if result != 1:
        raise RuntimeError('OpenSSL operation failed')


def params(**values):
    buffers = [C.create_string_buffer(v) for v in values.values()]
    entries = [Param(k.encode(), 5, C.cast(b, P), len(v), 0)
               for (k, v), b in zip(values.items(), buffers)]
    return (Param * (len(entries) + 1))(*entries, Param()), buffers


class Key:
    def __init__(self, algorithm, *, seed=None, public=None):
        values = {'seed': seed} if seed is not None else {'pub': public}
        context = ctx_new(None, algorithm.encode(), None)
        if not context:
            raise RuntimeError('OpenSSL algorithm unavailable: ' + algorithm)
        try:
            check(from_init(context))
            par, keepalive = params(**values)
            self.key = P()
            check(fromdata(context, C.byref(self.key), 0x87 if seed is not None else 0x86, par))
        finally:
            ctx_free(context)

    def close(self):
        if self.key:
            key_free(self.key)
            self.key = None

    def public(self):
        size = S()
        check(get_octets(self.key, b'pub', None, 0, C.byref(size)))
        out = C.create_string_buffer(size.value)
        check(get_octets(self.key, b'pub', out, size.value, C.byref(size)))
        return out.raw[:size.value]

    def encapsulate(self):
        context = ctx_key(None, self.key, None)
        try:
            check(enc_init(context, None))
            ct, ss, cn, sn = C.create_string_buffer(1568), C.create_string_buffer(32), S(1568), S(32)
            check(enc(context, ct, C.byref(cn), ss, C.byref(sn)))
            assert cn.value == 1568 and sn.value == 32
            return ct.raw, ss.raw
        finally:
            ctx_free(context)

    def decapsulate(self, ciphertext):
        context = ctx_key(None, self.key, None)
        try:
            check(dec_init(context, None))
            out, n = C.create_string_buffer(32), S(32)
            check(dec(context, out, C.byref(n), ciphertext, len(ciphertext)))
            assert n.value == 32
            return out.raw
        finally:
            ctx_free(context)

    def sign(self, message, context=b''):
        md = md_new()
        try:
            par, keepalive = params(**{'context-string': context})
            check(sign_init(md, None, None, None, None, self.key, par))
            out, size = C.create_string_buffer(4627), S(4627)
            check(sign(md, out, C.byref(size), message, len(message)))
            assert size.value == 4627
            return out.raw
        finally:
            md_free(md)

    def verify(self, message, signature, context=b''):
        md = md_new()
        try:
            par, keepalive = params(**{'context-string': context})
            check(verify_init(md, None, None, None, None, self.key, par))
            return verify(md, signature, len(signature), message, len(message)) == 1
        finally:
            md_free(md)


def aead(key, nonce, data, aad, encrypt):
    ctx = cipher_new()
    init, update, final = (einit, eupdate, efinal) if encrypt else (dinit, dupdate, dfinal)
    try:
        check(init(ctx, chacha(), None, key, nonce))
        n = I()
        check(update(ctx, None, C.byref(n), aad, len(aad)))
        body = data if encrypt else data[:-16]
        out = C.create_string_buffer(len(body) + 16)
        check(update(ctx, out, C.byref(n), body, len(body)))
        used = n.value
        if not encrypt:
            check(ctrl(ctx, 0x11, 16, data[-16:]))
        check(final(ctx, C.byref(out, used), C.byref(n)))
        result = out.raw[:used + n.value]
        if encrypt:
            tag = C.create_string_buffer(16)
            check(ctrl(ctx, 0x10, 16, tag))
            result += tag.raw
        return result
    finally:
        cipher_free(ctx)


if __name__ == '__main__':
    for algo, size in [('ML-KEM-1024', 64), ('ML-DSA-87', 32)]:
        key = Key(algo, seed=bytes(range(size)))
        pub = Key(algo, public=key.public())
        if size == 64:
            ct, ss = pub.encapsulate()
            assert key.decapsulate(ct) == ss
        else:
            assert pub.verify(b'validation', key.sign(b'validation', b'context'), b'context')
        key.close()
        pub.close()
    ct = aead(bytes(32), bytes(12), b'validation', b'aad', True)
    assert aead(bytes(32), bytes(12), ct, b'aad', False) == b'validation'
    print(version, 'backend self-check passed')
