import struct
from ..exceptions import SnmpDecryptionError
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from typing import Callable, Type, Any


def encrypt_data(key: bytes, data: bytes, msgsecurityparams: list[Any]):
    # engine_boots = msgsecurityparams[1]
    # rand_ = random.randrange(0, 0xFFFFFFFF)

    # salt = struct.pack(
    #     'B' * 8,
    #     engine_boots >> 24 & 0xFF,
    #     engine_boots >> 16 & 0xFF,
    #     engine_boots >> 8 & 0xFF,
    #     engine_boots & 0xFF,
    #     rand_ >> 24 & 0xFF,
    #     rand_ >> 16 & 0xFF,
    #     rand_ >> 8 & 0xFF,
    #     rand_ & 0xFF)

    msgsecurityparams[5] = salt = get_random_bytes(8)

    des_key = key[:8]
    iv = struct.pack('B' * 8, *map(lambda x, y: x ^ y, salt, key[8:16]))

    obj = DES.new(des_key, DES.MODE_CBC, iv)  # type: ignore
    return obj.encrypt(pad(data, 8))


def decrypt_data(key: bytes, data: bytes, msgsecurityparams: list[Any]):
    salt = msgsecurityparams[5]

    if len(salt) != 8:
        raise SnmpDecryptionError

    des_key = key[:8]
    iv = struct.pack('B' * 8, *map(lambda x, y: x ^ y, salt, key[8:16]))

    if len(data) % 8 != 0:
        raise SnmpDecryptionError

    obj = DES.new(des_key, DES.MODE_CBC, iv)  # type: ignore
    return obj.decrypt(data)


def _get_pre_iv(engine_boots: int, engine_time: int):
    return struct.pack(
        'B' * 8,
        engine_boots >> 24 & 0xff,
        engine_boots >> 16 & 0xff,
        engine_boots >> 8 & 0xff,
        engine_boots & 0xff,
        engine_time >> 24 & 0xff,
        engine_time >> 16 & 0xff,
        engine_time >> 8 & 0xff,
        engine_time & 0xff
    )


def encrypt_data_aes(key: bytes, data: bytes, msgsecurityparams: list[Any]):
    msgsecurityparams[5] = salt = get_random_bytes(8)
    pre_iv = _get_pre_iv(msgsecurityparams[1], msgsecurityparams[2])
    iv = pre_iv + salt
    obj = AES.new(key[:16], AES.MODE_CFB, iv, segment_size=128)  # type: ignore
    return obj.encrypt(pad(data, 16))


def decrypt_data_aes(key: bytes, data: bytes, msgsecurityparams: list[Any]):
    pre_iv = _get_pre_iv(msgsecurityparams[1], msgsecurityparams[2])
    iv = pre_iv + msgsecurityparams[5]
    obj = AES.new(key[:16], AES.MODE_CFB, iv, segment_size=128)  # type: ignore
    return obj.decrypt(pad(data, 16))


class Priv:
    encrypt: Callable[[bytes, bytes, Any], bytes]
    decrypt: Callable[[bytes, Any, Any], bytes]


class USM_PRIV_CBC56_DES(Priv):
    encrypt = encrypt_data
    decrypt = decrypt_data


class USM_PRIV_CFB128_AES(Priv):
    encrypt = encrypt_data_aes
    decrypt = decrypt_data_aes


PRIV_PROTO: dict[str, Type[Priv]] = {
    'USM_PRIV_CBC56_DES': USM_PRIV_CBC56_DES,
    'USM_PRIV_CFB128_AES': USM_PRIV_CFB128_AES,
}
