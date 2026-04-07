import asyncio
import logging
from typing import Any, Optional, Type
from ..asn1 import Tag, TOid, TValue
from ..exceptions import SnmpTimeoutError, SnmpAuthV3Exception
from ..protocol import SnmpProtocol, _ERROR_STATUS_TO_EXCEPTION
from .auth import Auth
from .encr import Priv
from .package import Package, SnmpV3Message

_RESPONSE_PDU_ID = 2
_REPORT_PDU_ID = 8
_REPORT_OID_EXCEPTIONS = {
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0): 'Unsupported securityLevel',
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0): 'Not in time window',
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0): 'Unknown user',
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0): 'Unknown snmpEngineID',
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0): 'Wrong digest value',
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0): 'Decryption error',
}


class SnmpV3Protocol(SnmpProtocol):
    __slots__ = ('_params', )

    def datagram_received(self, data: bytes, addr: Any):
        # NOTE on typing
        # https://docs.python.org/3/library/asyncio-protocol.html
        # addr is the address of the peer sending the data;
        # the exact format depends on the transport.
        pkg = Package()
        try:
            pkg.decode(data)
        except Exception:
            logging.error(self._log_with_suffix('Failed to decode package'))
        else:
            pid = pkg.request_id
            if pid not in self.requests:
                logging.error(
                    self._log_with_suffix(f'Unknown package pid {pid}'))
            else:
                # keep the connection params here as we need the updated
                # engine_id, engine_time, engine_boots for further requests
                self._params = pkg.msgsecurityparameters
                self.requests[pid].set_result((pkg, len(data)))

    def get_params(self):
        return self._params

    async def _send_encrypted(self, pkg: SnmpV3Message,
                              auth_proto: Optional[Type[Auth]],
                              auth_key: Optional[bytes],
                              priv_proto: Optional[Type[Priv]],
                              priv_key: Optional[bytes],
                              timeout: Optional[float] = 10.0
                              ) -> tuple[list[tuple[TOid, Tag, TValue]], int]:
        self._request_id += 1
        self._request_id %= 0x10000

        pkg.request_id = pid = self._request_id
        if priv_proto:
            pkg.msgflags = b'\x03'
            pkg.encrypt(priv_proto, priv_key)  # type: ignore
            msg = pkg.encode_auth(auth_proto, auth_key)  # type: ignore
        elif auth_proto:
            pkg.msgflags = b'\x01'
            msg = pkg.encode_auth(auth_proto, auth_key)  # type: ignore
        else:
            pkg.msgflags = b'\x00'
            msg = pkg.encode()

        fut = self.requests[pid] = self.loop.create_future()
        fut.add_done_callback(
            lambda _: self.requests.pop(pid) if pid in self.requests else None)

        self.transport.sendto(msg, self.target)

        done, _ = await asyncio.wait((fut, ), timeout=timeout)
        if not done:
            fut.cancel()
            logging.warning(
                self._log_with_suffix(
                    f'Package pid {pid} timed out after {timeout} seconds'))
            raise SnmpTimeoutError

        res, size = fut.result()

        if priv_proto and res.msgflags == b'\x03':
            res.decrypt(priv_proto, priv_key)

        _, _, pdu = res.msgdata
        pdu_id, _, error_status, error_index, vbs = pdu
        if pdu_id == _REPORT_PDU_ID:
            msg = None
            if len(vbs) == 0:
                msg = 'Received a report pdu'
            else:
                oid = vbs[0]
                oidstr = '.'.join(map(str, oid))
                msgfb = f'Received a report pdu `{oidstr}`'
                msg = _REPORT_OID_EXCEPTIONS.get(oid, msgfb)
            raise SnmpAuthV3Exception(msg)

        if pdu_id != _RESPONSE_PDU_ID:
            raise Exception('Expected a response pdu')

        if error_status != 0:
            oid = None
            if error_index != 0 and error_index < len(vbs):
                # error_index can be equal to pdu.max_repetitions
                # error_index starts at 1
                oid = vbs[error_index - 1][0]
            exception = _ERROR_STATUS_TO_EXCEPTION[error_status](oid)
            raise exception

        return vbs, size

    async def send_encrypted(self, pkg: SnmpV3Message,
                             auth_proto: Optional[Type[Auth]],
                             auth_key: Optional[bytes],
                             priv_proto: Optional[Type[Priv]],
                             priv_key: Optional[bytes]
                             ) -> tuple[list[tuple[TOid, Tag, TValue]], int]:
        for timeout in self._timeouts:
            try:
                res = await self._send_encrypted(
                    pkg, auth_proto, auth_key, priv_proto, priv_key, timeout)
            except SnmpTimeoutError:
                pass
            else:
                break
        else:
            raise SnmpTimeoutError
        return res
