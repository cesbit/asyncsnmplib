import asyncio
from .exceptions import (
    SnmpNoConnection,
    SnmpErrorNoSuchName,
    SnmpTooMuchRows,
    SnmpNoAuthParams,
)
from .package import SnmpMessage
from .pdu import SnmpGet, SnmpGetNext, SnmpGetBulk
from .protocol import SnmpProtocol
from .v3.auth import AUTH_PROTO
from .v3.encr import PRIV_PROTO
from .v3.package import SnmpV3Message
from .v3.protocol import SnmpV3Protocol


class Snmp:
    version = 1  # = v2

    def __init__(self, host, port=161, community='public', max_rows=10000):
        self._loop = asyncio.get_event_loop()
        self._protocol = None
        self._transport = None
        self.host = host
        self.port = port
        self.community = community
        self.max_rows = max_rows

    async def connect(self, timeout=10):
        try:
            infos = await self._loop.getaddrinfo(self.host, self.port)
            family, *_, addr = infos[0]
            transport, protocol = await asyncio.wait_for(
                self._loop.create_datagram_endpoint(
                    lambda: SnmpProtocol(addr),
                    # remote_addr=(self.host, self.port),
                    family=family),
                timeout=timeout)
        except Exception:
            raise SnmpNoConnection
        self._protocol = protocol
        self._transport = transport

    def _get(self, oids, timeout=None):
        if self._transport is None:
            raise SnmpNoConnection
        pdu = SnmpGet(0, oids)
        message = SnmpMessage.make(self.version, self.community, pdu)
        if timeout:
            return self._protocol._send(message, timeout)
        else:
            return self._protocol.send(message)

    def _get_next(self, oids):
        if self._transport is None:
            raise SnmpNoConnection
        pdu = SnmpGetNext(0, oids)
        message = SnmpMessage.make(self.version, self.community, pdu)
        return self._protocol.send(message)

    def _get_bulk(self, oids):
        if self._transport is None:
            raise SnmpNoConnection
        pdu = SnmpGetBulk(0, oids)
        message = SnmpMessage.make(self.version, self.community, pdu)
        return self._protocol.send(message)

    async def get(self, oid, timeout=None):
        vbs = await self._get([oid], timeout)
        return vbs[0]

    async def get_next(self, oid):
        vbs = await self._get_next([oid])
        return vbs[0]

    async def get_next_multi(self, oids):
        vbs = await self._get_next(oids)
        return [(oid, value) for oid, _, value in vbs if oid[:-1] in oids]

    async def walk(self, oid, recursive=True):
        next_oid = oid
        prefixlen = len(oid)
        rows = []

        while True:
            vbs = await self._get_bulk([next_oid])

            new_rows = [
                (oid_, value)
                for oid_, tag, value in vbs
                if oid_[:prefixlen] == oid and
                (recursive or oid_[-1] == 0) and
                value is not None
            ]
            rows.extend(new_rows)

            if len(rows) > self.max_rows:
                raise SnmpTooMuchRows

            if len(vbs) > len(new_rows):
                break

            next_oid = vbs[-1][0]

        return rows

    def close(self):
        if self._transport is not None and not self._transport.is_closing():
            self._transport.close()
        self._protocol = None
        self._transport = None


class SnmpV1(Snmp):
    version = 0

    async def walk(self, oid, recursive=True):
        next_oid = oid
        prefixlen = len(oid)
        rows = []

        while True:
            try:
                vbs = await self._get_next([next_oid])
            except SnmpErrorNoSuchName:
                # snmp v1 uses error-status instead of end-of-mib exception
                break

            new_rows = [
                (oid_, value)
                for oid_, tag, value in vbs
                if oid_[:prefixlen] == oid and (recursive or oid_[-1] == 0)
            ]
            rows.extend(new_rows)

            if len(rows) > self.max_rows:
                raise SnmpTooMuchRows

            if len(vbs) > len(new_rows):
                break

            next_oid = vbs[-1][0]

        return rows


class SnmpV3(Snmp):
    version = 3

    def __init__(
            self,
            host,
            username,
            auth_proto='USM_AUTH_NONE',
            auth_passwd=None,
            priv_proto='USM_PRIV_NONE',
            priv_passwd=None,
            port=161,
            max_rows=10000):
        self._loop = asyncio.get_event_loop()
        self._protocol = None
        self._transport = None
        self.host = host
        self.port = port
        self.max_rows = max_rows
        self._auth_params = None
        self._username = username
        self._auth_hash = None
        self._auth_hash_localized = None
        self._priv_hash = None
        self._priv_hash_localized = None
        try:
            self._auth_proto = AUTH_PROTO[auth_proto]
        except KeyError:
            raise Exception('Supply valid auth_proto')
        try:
            self._priv_proto = PRIV_PROTO[priv_proto]
        except KeyError:
            raise Exception('Supply valid auth_proto')
        if self._priv_proto and not self._auth_proto:
            raise Exception('Supply auth_proto')
        if self._auth_proto:
            if auth_passwd is None:
                raise Exception('Supply auth_passwd')
            self._auth_hash = self._auth_proto.hash_passphrase(auth_passwd)
        if self._priv_proto:
            if priv_passwd is None:
                raise Exception('Supply priv_passwd')
            self._priv_hash = self._auth_proto.hash_passphrase(priv_passwd)

    async def connect(self, timeout=10):
        try:
            infos = await self._loop.getaddrinfo(self.host, self.port)
            family, *_, addr = infos[0]
            transport, protocol = await asyncio.wait_for(
                self._loop.create_datagram_endpoint(
                    lambda: SnmpV3Protocol(addr),
                    family=family),
                timeout=timeout)
        except Exception:
            raise SnmpNoConnection
        self._protocol = protocol
        self._transport = transport
        try:
            await self._get_auth_params()
        except Exception:
            raise SnmpNoAuthParams

    async def _get_auth_params(self, timeout=10):
        pdu = SnmpGet(0, [])
        message = SnmpV3Message.make(pdu, [b'', 0, 0, b'', b'', b''])
        # this request will not retry like the other requests
        pkg = await self._protocol._send(message, timeout=timeout)
        self._auth_params = \
            pkg.msgsecurityparameters[:3] + [self._username, b'\x00' * 12, b'']
        self._auth_hash_localized = self._auth_proto.localize(
            self._auth_hash, pkg.msgsecurityparameters[0]) \
            if self._auth_proto else None
        self._priv_hash_localized = self._auth_proto.localize(
            self._priv_hash, pkg.msgsecurityparameters[0]) \
            if self._priv_proto else None

    def _get(self, oids, timeout=None):
        if self._transport is None:
            raise SnmpNoConnection
        elif self._auth_params is None:
            raise SnmpNoAuthParams
        pdu = SnmpGet(0, oids)
        message = SnmpV3Message.make(pdu, self._auth_params)
        if timeout:
            return self._protocol._send_encrypted(
                message,
                self._auth_proto,
                self._auth_hash_localized,
                self._priv_proto,
                self._priv_hash_localized,
                timeout=timeout)
        else:
            return self._protocol.send_encrypted(
                message,
                self._auth_proto,
                self._auth_hash_localized,
                self._priv_proto,
                self._priv_hash_localized)

    def _get_next(self, oids):
        if self._transport is None:
            raise SnmpNoConnection
        elif self._auth_params is None:
            raise SnmpNoAuthParams
        pdu = SnmpGetNext(0, oids)
        message = SnmpV3Message.make(pdu, self._auth_params)
        return self._protocol.send_encrypted(
            message,
            self._auth_proto,
            self._auth_hash_localized,
            self._priv_proto,
            self._priv_hash_localized)

    def _get_bulk(self, oids):
        if self._transport is None:
            raise SnmpNoConnection
        elif self._auth_params is None:
            raise SnmpNoAuthParams
        pdu = SnmpGetBulk(0, oids)
        message = SnmpV3Message.make(pdu, self._auth_params)
        return self._protocol.send_encrypted(
            message,
            self._auth_proto,
            self._auth_hash_localized,
            self._priv_proto,
            self._priv_hash_localized)
