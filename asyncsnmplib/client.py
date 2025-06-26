import asyncio
import logging
from typing import Iterable, Optional, Tuple, List, Type
from .exceptions import (
    SnmpNoConnection,
    SnmpErrorNoSuchName,
    SnmpTimeoutError,
    SnmpTooMuchRows,
    SnmpNoAuthParams,
)
from .asn1 import Tag, TOid, TValue
from .package import SnmpMessage
from .pdu import SnmpGet, SnmpGetNext, SnmpGetBulk, ScopedPDU
from .protocol import SnmpProtocol, DEFAULT_TIMEOUTS
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
            loop: Optional[asyncio.AbstractEventLoop] = None,
            timeouts: tuple[int, ...] = DEFAULT_TIMEOUTS):
        self._loop = loop if loop else asyncio.get_running_loop()
        self._protocol = None
        self._transport = None
        self.host = host
        self.port = port
        self.community = community.encode()
        self.max_rows = max_rows
        self._timeouts = timeouts

    # On some systems it seems to be required to set the remote_addr argument
    # https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_datagram_endpoint
    async def connect(self, timeout: float = 10.0):
        try:
            infos = await self._loop.getaddrinfo(self.host, self.port)
            family, *_, addr = infos[0]
            transport, protocol = await asyncio.wait_for(
                self._loop.create_datagram_endpoint(
                    lambda: SnmpProtocol(addr, timeouts=self._timeouts),
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
        pdu = SnmpGet(variable_bindings=oids)
        message = SnmpMessage.make(self.version, self.community, pdu)
        if timeout:
            return self._protocol._send(message, timeout)
        else:
            return self._protocol.send(message)

    def _get_next(self, oids):
        if self._protocol is None:
            raise SnmpNoConnection
        pdu = SnmpGetNext(variable_bindings=oids)
        message = SnmpMessage.make(self.version, self.community, pdu)
        return self._protocol.send(message)

    def _get_bulk(self, oids):
        if self._protocol is None:
            raise SnmpNoConnection
        pdu = SnmpGetBulk(variable_bindings=oids)
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

    async def walk(self, oid: TOid, is_table: bool,
                   ) -> List[Tuple[TOid, TValue]]:
        next_oid = oid
        prefixlen = len(oid)
        rows = []

        while True:
            vbs = await self._get_bulk([next_oid])
            for next_oid, _, value in vbs:
                if next_oid[:prefixlen] != oid or value is None:
                    # we're done
                    break

                if is_table or next_oid[prefixlen + 1] == 0:
                    # this is a row we want in the result, otherwise
                    # we are in a table
                    if len(rows) == self.max_rows:
                        raise SnmpTooMuchRows
                    rows.append((next_oid, value))

                continue
            else:
                # we might have more, check if we are in a table
                if not is_table and next_oid[prefixlen + 1] != 0:
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

    async def walk(self, oid: TOid, is_table: bool,
                   ) -> List[Tuple[TOid, TValue]]:
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

                if is_table or next_oid[prefixlen + 1] == 0:
                    # this is a row we want in the result, otherwise
                    # we are in a table
                    if len(rows) == self.max_rows:
                        raise SnmpTooMuchRows
                    rows.append((next_oid, value))

                continue
            else:
                # we might have more, check if we are in a table
                if not is_table and next_oid[prefixlen + 1] != 0:
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
            loop: Optional[asyncio.AbstractEventLoop] = None,
            timeouts: tuple[int, ...] = DEFAULT_TIMEOUTS):
        self._loop = loop if loop else asyncio.get_running_loop()
        self._protocol = None
        self._transport = None
        self.host = host
        self.port = port
        self.max_rows = max_rows
        self._auth_params = None
        self._username = username.encode()
        self._auth_proto = None
        self._auth_hash = None
        self._auth_hash_localized = None
        self._priv_proto = None
        self._priv_hash = None
        self._priv_hash_localized = None
        self._timeouts = timeouts
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
                    lambda: SnmpV3Protocol(addr, timeouts=self._timeouts),
                    remote_addr=(self.host, self.port),
                    family=family),
                timeout=timeout)
        except Exception:
            raise SnmpNoConnection
        self._protocol = protocol
        self._transport = transport
        try:
            await self._get_auth_params()
        except SnmpTimeoutError:
            raise SnmpTimeoutError
        except Exception:
            raise SnmpNoAuthParams

    async def _get_auth_params(self):
        assert self._protocol is not None

        # retrieve engine_id
        pdu = SnmpGet(0, variable_bindings=[])
        spdu = ScopedPDU(pdu)
        params = (b'', 0, 0, b'', b'', b'')
        message = SnmpV3Message.make(spdu, params)

        # raises exception when timeout
        await self._protocol.send(message)

        params = self._protocol.get_params()
        assert params  # params is always set when a valid package is recieved

        try:
            engine_id = params[0]
            self._auth_hash_localized = self._auth_proto.localize(
                self._auth_hash, engine_id) \
                if self._auth_proto else None
            self._priv_hash_localized = self._auth_proto.localize(
                self._priv_hash, engine_id) \
                if self._auth_proto and self._priv_proto else None
        except Exception:
            logging.exception('')
            raise SnmpNoAuthParams

    def _get(self, oids, timeout=None):
        if self._protocol is None:
            raise SnmpNoConnection
        params = self._protocol.get_params()
        if params is None:
            raise SnmpNoAuthParams
        pdu = SnmpGet(variable_bindings=oids)
        spdu = ScopedPDU(pdu)
        params = [*params[:3], self._username, b'', b'']
        message = SnmpV3Message.make(spdu, params)
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
        params = self._protocol.get_params()
        if params is None:
            raise SnmpNoAuthParams
        pdu = SnmpGetNext(variable_bindings=oids)
        spdu = ScopedPDU(pdu)
        params = [*params[:3], self._username, b'', b'']
        message = SnmpV3Message.make(spdu, params)
        return self._protocol.send_encrypted(
            message,
            self._auth_proto,
            self._auth_hash_localized,
            self._priv_proto,
            self._priv_hash_localized)

    def _get_bulk(self, oids):
        if self._protocol is None:
            raise SnmpNoConnection
        params = self._protocol.get_params()
        if params is None:
            raise SnmpNoAuthParams
        pdu = SnmpGetBulk(variable_bindings=oids)
        spdu = ScopedPDU(pdu)
        params = [*params[:3], self._username, b'', b'']
        message = SnmpV3Message.make(spdu, params)
        return self._protocol.send_encrypted(
            message,
            self._auth_proto,
            self._auth_hash_localized,
            self._priv_proto,
            self._priv_hash_localized)
