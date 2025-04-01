import hmac
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
from typing import Callable, Type, Dict


def hash_passphrase(passphrase, hash_func):
    hasher = hash_func()
    buff = passphrase * (64 // len(passphrase) + 1)
    ln = len(buff)
    count = 0
    mk = 0
    while count < 16384:
        i = mk + 64
        if i < ln:
            hasher.update(buff[mk:i])
            mk = i
        else:
            hasher.update(
                buff[mk:ln] + buff[0:i - ln]
            )
            mk = i - ln
        count += 1
    digest = hasher.digest()
    return digest


def localize_key(key, engineid, hash_func):
    return hash_func(key + engineid + key).digest()


# RFC3414: A.2.1
def hash_passphrase_md5(passphrase):
    return hash_passphrase(passphrase.encode(), md5)


# RFC3414: A.2.2
def hash_passphrase_sha(passphrase):
    return hash_passphrase(passphrase.encode(), sha1)


def hash_passphrase_sha224(passphrase):
    return hash_passphrase(passphrase.encode(), sha224)


def hash_passphrase_sha256(passphrase):
    return hash_passphrase(passphrase.encode(), sha256)


def hash_passphrase_sha384(passphrase):
    return hash_passphrase(passphrase.encode(), sha384)


def hash_passphrase_sha512(passphrase):
    return hash_passphrase(passphrase.encode(), sha512)


def localize_key_md5(key, engineid):
    return localize_key(key, engineid, md5)


def localize_key_sha(key, engineid):
    return localize_key(key, engineid, sha1)


def localize_key_sha224(key, engineid):
    return localize_key(key, engineid, sha224)


def localize_key_sha256(key, engineid):
    return localize_key(key, engineid, sha256)


def localize_key_sha384(key, engineid):
    return localize_key(key, engineid, sha384)


def localize_key_sha512(key, engineid):
    return localize_key(key, engineid, sha512)


# RFC3414: 6.3.1
def authenticate_md5(auth_key, msg):
    mac = hmac.new(auth_key, msg, md5)
    d = mac.digest()
    return d[:12]


# RFC3414: 7.3.1
def authenticate_sha(auth_key, msg):
    mac = hmac.new(auth_key, msg, sha1)
    d = mac.digest()
    return d[:12]


def authenticate_sha224(auth_key, msg):
    mac = hmac.new(auth_key, msg, sha224)
    d = mac.digest()
    return d[:16]


def authenticate_sha256(auth_key, msg):
    mac = hmac.new(auth_key, msg, sha256)
    d = mac.digest()
    return d[:24]


def authenticate_sha384(auth_key, msg):
    mac = hmac.new(auth_key, msg, sha384)
    d = mac.digest()
    return d[:32]


def authenticate_sha512(auth_key, msg):
    mac = hmac.new(auth_key, msg, sha512)
    d = mac.digest()
    return d[:48]


class Auth:
    hash_passphrase: Callable
    localize: Callable
    auth: Callable
    sz: int


class USM_AUTH_HMAC96_MD5(Auth):
    hash_passphrase = hash_passphrase_md5
    localize = localize_key_md5
    auth = authenticate_md5
    sz = 12


class USM_AUTH_HMAC96_SHA(Auth):
    hash_passphrase = hash_passphrase_sha
    localize = localize_key_sha
    auth = authenticate_sha
    sz = 12


class USM_AUTH_HMAC128_SHA224(Auth):
    hash_passphrase = hash_passphrase_sha224
    localize = localize_key_sha224
    auth = authenticate_sha224
    sz = 16


class USM_AUTH_HMAC192_SHA256(Auth):
    hash_passphrase = hash_passphrase_sha256
    localize = localize_key_sha256
    auth = authenticate_sha256
    sz = 24


class USM_AUTH_HMAC256_SHA384(Auth):
    hash_passphrase = hash_passphrase_sha384
    localize = localize_key_sha384
    auth = authenticate_sha384
    sz = 32


class USM_AUTH_HMAC384_SHA512(Auth):
    hash_passphrase = hash_passphrase_sha512
    localize = localize_key_sha512
    auth = authenticate_sha512
    sz = 48


AUTH_PROTO: Dict[str, Type[Auth]] = {
    'USM_AUTH_HMAC96_MD5': USM_AUTH_HMAC96_MD5,
    'USM_AUTH_HMAC96_SHA': USM_AUTH_HMAC96_SHA,
    'USM_AUTH_HMAC128_SHA224': USM_AUTH_HMAC128_SHA224,
    'USM_AUTH_HMAC192_SHA256': USM_AUTH_HMAC192_SHA256,
    'USM_AUTH_HMAC256_SHA384': USM_AUTH_HMAC256_SHA384,
    'USM_AUTH_HMAC384_SHA512': USM_AUTH_HMAC384_SHA512,
}
