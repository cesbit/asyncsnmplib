import asyncio
from typing import Iterable, Optional, Tuple, List, Type
from .exceptions import (
    SnmpNoConnection,
    SnmpErrorNoSuchName,
    SnmpTooMuchRows,
    SnmpNoAuthParams,
)
from .asn1 import Tag, TOid, TValue
from .package import SnmpMessage
from .pdu import SnmpGet, SnmpGetNext, SnmpGetBulk
from .protocol import SnmpProtocol
from .v3.auth import Auth
from .v3.encr import Priv
from .v3.package import SnmpV3Message
from .v3.protocol import SnmpV3Protocol


class Snmp:
    version = 1  # = v2

    def __init__(
            self,
            host: str,
            port: int = 161,
            community: str = 'public',
            max_rows: int = 10_000,
            loop: Optional[asyncio.AbstractEventLoop] = None):
        self._loop = loop if loop else asyncio.get_running_loop()
        self._protocol = None
        self._transport = None
        self.host = host
        self.port = port
        self.community = community
        self.max_rows = max_rows

    # On some systems it seems to be required to set the remote_addr argument
    # https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_datagram_endpoint
    async def connect(self, timeout: float = 10.0):
        try:
            infos = await self._loop.getaddrinfo(self.host, self.port)
            family, *_, addr = infos[0]
            transport, protocol = await asyncio.wait_for(
                self._loop.create_datagram_endpoint(
                    lambda: SnmpProtocol(addr),
                    remote_addr=(self.host, self.port),
                    family=family),
                timeout=timeout)
        except Exception:
            raise SnmpNoConnection
        self._protocol = protocol
        self._transport = transport

    def _get(self, oids, timeout=None):
        if self._protocol is None:
            raise SnmpNoConnection
        pdu = SnmpGet(0, oids)
        message = SnmpMessage.make(self.version, self.community, pdu)
        if timeout:
            return self._protocol._send(message, timeout)
        else:
            return self._protocol.send(message)

    def _get_next(self, oids):
        if self._protocol is None:
            raise SnmpNoConnection
        pdu = SnmpGetNext(0, oids)
        message = SnmpMessage.make(self.version, self.community, pdu)
        return self._protocol.send(message)

    def _get_bulk(self, oids):
        if self._protocol is None:
            raise SnmpNoConnection
        pdu = SnmpGetBulk(0, oids)
        message = SnmpMessage.make(self.version, self.community, pdu)
        return self._protocol.send(message)

    async def get(self, oid: TOid, timeout: Optional[float] = None
                  ) -> Tuple[TOid, Tag, TValue]:
        vbs = await self._get([oid], timeout)
        return vbs[0]

    async def get_next(self, oid: TOid) -> Tuple[TOid, Tag, TValue]:
        vbs = await self._get_next([oid])
        return vbs[0]

    async def get_next_multi(self, oids: Iterable[TOid]
                             ) -> List[Tuple[TOid, TValue]]:
        vbs = await self._get_next(oids)
        return [(oid, value) for oid, _, value in vbs if oid[:-1] in oids]

    async def walk(self, oid: TOid) -> List[Tuple[TOid, TValue]]:
        next_oid = oid
        prefixlen = len(oid)
        rows = []

        while True:
            vbs = await self._get_bulk([next_oid])
            for next_oid, _, value in vbs:
                if next_oid[:prefixlen] != oid or value is None:
                    # we're done
                    break

                if next_oid[prefixlen + 1] == 0:
                    # this is a row we want in the result, otherwise
                    # we are in a table
                    if len(rows) == self.max_rows:
                        raise SnmpTooMuchRows
                    rows.append((next_oid, value))

                continue
            else:
                # we might have more, check if we are in a table
                if next_oid[prefixlen + 1] != 0:
                    next_oid = (*oid, next_oid[prefixlen] + 1)
                continue
            break

        return rows

    def close(self):
        if self._transport is not None and not self._transport.is_closing():
            self._transport.close()
        self._protocol = None
        self._transport = None


class SnmpV1(Snmp):
    version = 0

    async def walk(self, oid: TOid) -> List[Tuple[TOid, TValue]]:
        next_oid = oid
        prefixlen = len(oid)
        rows = []

        while True:
            try:
                vbs = await self._get_next([next_oid])
            except SnmpErrorNoSuchName:
                # snmp v1 uses error-status instead of end-of-mib exception
                break

            for next_oid, _, value in vbs:
                if next_oid[:prefixlen] != oid:
                    # we're done
                    break

                if next_oid[prefixlen + 1] == 0:
                    # this is a row we want in the result, otherwise
                    # we are in a table
                    if len(rows) == self.max_rows:
                        raise SnmpTooMuchRows
                    rows.append((next_oid, value))

                continue
            else:
                # we might have more, check if we are in a table
                if next_oid[prefixlen + 1] != 0:
                    next_oid = (*oid, next_oid[prefixlen] + 1)
                continue
            break

        return rows


class SnmpV3(Snmp):
    version = 3

    def __init__(
            self,
            host: str,
            username: str,
            auth: Optional[Tuple[Type[Auth], str]] = None,
            priv: Optional[Tuple[Type[Priv], str]] = None,
            port: int = 161,
            max_rows: int = 10_000,
            loop: Optional[asyncio.AbstractEventLoop] = None):
        self._loop = loop if loop else asyncio.get_running_loop()
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
        if auth is not None:
            self._auth_proto, auth_passwd = auth
            self._auth_hash = self._auth_proto.hash_passphrase(auth_passwd)
            if priv is not None:
                self._priv_proto, priv_passwd = priv
                self._priv_hash = self._auth_proto.hash_passphrase(priv_passwd)

    # On some systems it seems to be required to set the remote_addr argument
    # https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_datagram_endpoint
    async def connect(self, timeout: float = 10.0):
        try:
            infos = await self._loop.getaddrinfo(self.host, self.port)
            family, *_, addr = infos[0]
            transport, protocol = await asyncio.wait_for(
                self._loop.create_datagram_endpoint(
                    lambda: SnmpV3Protocol(addr),
                    remote_addr=(self.host, self.port),
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
        # TODO for long requests this will need to be refreshed
        # https://datatracker.ietf.org/doc/html/rfc3414#section-2.2.3
        assert self._protocol is not None
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
        if self._protocol is None:
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
        if self._protocol is None:
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
        if self._protocol is None:
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
