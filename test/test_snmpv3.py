import unittest
import asyncio
from asyncsnmplib.client import SnmpV3, Snmp
from asyncsnmplib.v3.auth import AUTH_PROTO, USM_AUTH_HMAC96_SHA, USM_AUTH_HMAC192_SHA256, USM_AUTH_HMAC96_MD5, USM_AUTH_HMAC128_SHA224, USM_AUTH_HMAC256_SHA384, USM_AUTH_HMAC384_SHA512
from asyncsnmplib.v3.encr import PRIV_PROTO, USM_PRIV_CFB128_AES

HOST = 'localhost'
OID = (1, 3, 6, 1, 2, 1, 2, 2, 1)
IS_TABLE = True


class Test0(unittest.TestCase):
    def test0(self):
        cl = SnmpV3(HOST, 'user2', (USM_AUTH_HMAC96_SHA, 'Password1'), (USM_PRIV_CFB128_AES, 'Password1'), loop=loop)
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test1(self):
        # will return error as this user2 usmmodel requires auth_proto, auth_key, priv_proto, priv_key
        cl = SnmpV3(HOST, 'user2', loop=loop)
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test2(self):
        # will return error as this user2 usmmodel requires priv_proto, priv_key
        cl = SnmpV3(HOST, 'user2', (USM_AUTH_HMAC96_SHA, 'Password1'), loop=loop)
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test3(self):
        # will return error as this user2 usmmodel requires priv_proto, priv_key, regardless of invalid auth_key
        cl = SnmpV3(HOST, 'user2', (USM_AUTH_HMAC96_SHA, 'INVALID'), loop=loop)
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    # def test4(self):
    #     # will timeout as priv_key is incorrect
    #     cl = SnmpV3(HOST, 'user2', (USM_AUTH_HMAC96_SHA, 'INVALID'), (USM_PRIV_CFB128_AES, 'Password1'), loop=loop)  # timeout
    #     loop.run_until_complete(cl.connect())
    #     with self.assertRaises(Exception):
    #         loop.run_until_complete(cl.walk(OID, IS_TABLE))
    #     cl.close()

    # def test5(self):
    #     # will timeout as priv_key is incorrect
    #     cl = SnmpV3(HOST, 'user2', (USM_AUTH_HMAC96_SHA, 'Password1'), (USM_PRIV_CFB128_AES, 'INVALID'), loop=loop)  # timeout
    #     loop.run_until_complete(cl.connect())
    #     with self.assertRaises(Exception):
    #         loop.run_until_complete(cl.walk(OID, IS_TABLE))
    #     cl.close()

    def test_mda(self):
        cl = SnmpV3(HOST, 'user11', (USM_AUTH_HMAC96_MD5, 'Password11'), loop=loop)
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test_sha(self):
        cl = SnmpV3(HOST, 'user1', (USM_AUTH_HMAC96_SHA, 'Password1'), loop=loop)
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test_sha224(self):
        cl = SnmpV3(HOST, 'user12', (USM_AUTH_HMAC128_SHA224, 'Password12'), loop=loop)
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test_sha256(self):
        cl = SnmpV3(HOST, 'user13', (USM_AUTH_HMAC192_SHA256, 'Password12'), loop=loop)
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test_sha384(self):
        cl = SnmpV3(HOST, 'user14', (USM_AUTH_HMAC256_SHA384, 'Password12'), loop=loop)
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test_sha512(self):
        cl = SnmpV3(HOST, 'user15', (USM_AUTH_HMAC384_SHA512, 'Password12'), loop=loop)
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test11(self):
        cl = SnmpV3(HOST, 'user1', (USM_AUTH_HMAC96_SHA, 'Password2'), loop=loop)
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test12(self):
        cl = SnmpV3(HOST, 'user1', loop=loop)
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test20(self):
        cl = SnmpV3(HOST, 'user', loop=loop)
        loop.run_until_complete(cl.connect())
        res = loop.run_until_complete(cl.walk(OID, IS_TABLE))
        self.assertTrue(len(res) > 1)
        cl.close()

    def test21(self):
        cl = SnmpV3(HOST, 'user', (USM_AUTH_HMAC96_SHA, 'Password1'), loop=loop)
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()


class Test1(unittest.TestCase):

    # def test0(self):
    #     cl = SnmpV3(HOST, 'user3', (USM_AUTH_HMAC96_SHA, 'Password1'), (USM_PRIV_CFB128_AES, 'Password1'), loop=loop)  # timeout
    #     loop.run_until_complete(cl.connect())
    #     with self.assertRaises(Exception):
    #         loop.run_until_complete(cl.walk(OID, IS_TABLE))
    #     cl.close()

    def test1(self):
        cl = SnmpV3(HOST, 'user3', (USM_AUTH_HMAC96_SHA, 'Password1'), loop=loop)
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()

    def test2(self):
        cl = SnmpV3(HOST, 'user3', loop=loop)
        loop.run_until_complete(cl.connect())
        with self.assertRaises(Exception):
            loop.run_until_complete(cl.walk(OID, IS_TABLE))
        cl.close()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    unittest.main()
