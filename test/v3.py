import asyncio
import os
import unittest
from asyncsnmplib.client import SnmpV3
from asyncsnmplib.v3.auth import USM_AUTH_HMAC96_SHA
from asyncsnmplib.v3.auth import USM_AUTH_HMAC192_SHA256
from asyncsnmplib.v3.auth import USM_AUTH_HMAC96_MD5
from asyncsnmplib.v3.auth import USM_AUTH_HMAC128_SHA224
from asyncsnmplib.v3.auth import USM_AUTH_HMAC256_SHA384
from asyncsnmplib.v3.auth import USM_AUTH_HMAC384_SHA512
from asyncsnmplib.v3.encr import USM_PRIV_CFB128_AES

HOST = os.getenv('HOST', '127.0.0.1')
OID = (1, 3, 6, 1, 2, 1, 2, 2, 1)
IS_TABLE = True


def get_client(user_name, auth=None, priv=None):
    return SnmpV3(
        HOST,
        user_name,
        auth,
        priv,
        loop=loop,
        timeouts=(1, )
    )


class Test0(unittest.TestCase):
    def test0(self):
        cl = get_client('user2', (USM_AUTH_HMAC96_SHA, 'Password1'),
                        (USM_PRIV_CFB128_AES, 'Password1'))
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test1(self):
        cl = get_client('user2')
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test2(self):
        cl = get_client('user2', (USM_AUTH_HMAC96_SHA, 'Password1'))
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test3(self):
        cl = get_client('user2', (USM_AUTH_HMAC96_SHA, 'Password2'))
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test4(self):
        cl = get_client('user2', (USM_AUTH_HMAC96_SHA, 'Password2'),
                        (USM_PRIV_CFB128_AES, 'Password1'))  # timeout
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test5(self):
        cl = get_client('user2', (USM_AUTH_HMAC96_SHA, 'Password1'),
                        (USM_PRIV_CFB128_AES, 'Password2'))  # timeout
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test_mda(self):
        cl = get_client('user11', (USM_AUTH_HMAC96_MD5, 'Password11'))
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test_sha(self):
        cl = get_client('user1', (USM_AUTH_HMAC96_SHA, 'Password1'))
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test_sha224(self):
        cl = get_client('user12', (USM_AUTH_HMAC128_SHA224, 'Password12'))
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test_sha256(self):
        cl = get_client('user13', (USM_AUTH_HMAC192_SHA256, 'Password12'))
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test_sha384(self):
        cl = get_client('user14', (USM_AUTH_HMAC256_SHA384, 'Password12'))
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test_sha512(self):
        cl = get_client('user15', (USM_AUTH_HMAC384_SHA512, 'Password12'))
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test11(self):
        cl = get_client('user1', (USM_AUTH_HMAC96_SHA, 'Password2'))
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test12(self):
        cl = get_client('user1')
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test20(self):
        cl = get_client('user')
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test21(self):
        cl = get_client('user', (USM_AUTH_HMAC96_SHA, 'Password1'))
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()


class Test1(unittest.TestCase):

    def test0(self):
        cl = get_client('user3', (USM_AUTH_HMAC96_SHA, 'Password1'),
                        (USM_PRIV_CFB128_AES, 'Password1'))  # timeout
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test1(self):
        cl = get_client('user3', (USM_AUTH_HMAC96_SHA, 'Password1'))
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test2(self):
        cl = get_client('user3')
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()


if __name__ == '__main__':
    loop = asyncio.new_event_loop()

    unittest.main()
