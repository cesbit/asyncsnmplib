import struct
from hashlib import md5, sha1


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


def localize_key_md5(key, engineid):
    return localize_key(key, engineid, md5)


def localize_key_sha(key, engineid):
    return localize_key(key, engineid, sha1)


# RFC3414: 6.3.1
def authenticate_md5(auth_key, msg):
    extended = auth_key + b'\x00' * 48

    k1 = struct.pack('B' * 64, *map(lambda x, y: x ^ y, extended, [0x36] * 64))
    k2 = struct.pack('B' * 64, *map(lambda x, y: x ^ y, extended, [0x5C] * 64))

    d1 = md5(k1 + msg).digest()
    d2 = md5(k2 + d1).digest()

    return msg.replace(b'\x00' * 12, d2[:12], 1)


# RFC3414: 7.3.1
def authenticate_sha(auth_key, msg):
    extended = auth_key + b'\x00' * 44

    k1 = struct.pack('B' * 64, *map(lambda x, y: x ^ y, extended, [0x36] * 64))
    k2 = struct.pack('B' * 64, *map(lambda x, y: x ^ y, extended, [0x5C] * 64))

    d1 = sha1(k1 + msg).digest()
    d2 = sha1(k2 + d1).digest()

    return msg.replace(b'\x00' * 12, d2[:12], 1)


class USM_AUTH_HMAC96_MD5:
    hash_passphrase = hash_passphrase_md5
    localize = localize_key_md5
    auth = authenticate_md5


class USM_AUTH_HMAC96_SHA:
    hash_passphrase = hash_passphrase_sha
    localize = localize_key_sha
    auth = authenticate_sha


AUTH_PROTO = {
    'USM_AUTH_HMAC96_MD5': USM_AUTH_HMAC96_MD5,
    'USM_AUTH_HMAC96_SHA': USM_AUTH_HMAC96_SHA,
    'USM_AUTH_NONE': None,
}
