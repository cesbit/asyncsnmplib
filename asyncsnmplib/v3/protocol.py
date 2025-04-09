import asyncio
import logging
from typing import Any
from ..exceptions import SnmpTimeoutError, SnmpDecodeError
from ..protocol import SnmpProtocol, _ERROR_STATUS_TO_EXCEPTION
from .package_dec import Package

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
    __slots__ = ('_params')

    def datagram_received(self, data: bytes, addr: Any):
        # NOTE on typing
        # https://docs.python.org/3/library/asyncio-protocol.html
        # addr is the address of the peer sending the data;
        # the exact format depends on the transport.
        pkg = Package()
        try:
            pkg.decode(data)
        except Exception:
            # request_id is at the start of the pdu, when decode error occurs
            # before request_id is known we cannot do anything and the query
            # will time out
            pid = pkg.request_id
            if pid in self.requests:
                self.requests[pid].set_exception(SnmpDecodeError)
            elif pid is not None:
                logging.error(
                    self._log_with_suffix(f'Unknown package pid {pid}'))
            else:
                logging.error(
                    self._log_with_suffix('Failed to decode package'))
        else:
            pid = pkg.request_id
            if pid not in self.requests:
                logging.error(
                    self._log_with_suffix(f'Unknown package pid {pid}'))
            else:
                # keep the connection params here as we need the updated
                # engine_id, engine_time, engine_boots for further requests
                self._params = pkg.msgsecurityparameters
                self.requests[pid].set_result(pkg)

    def get_params(self):
        return self._params

    async def _send_encrypted(
            self, pkg, auth_proto, auth_key, priv_proto, priv_key, timeout=10):
        self._request_id += 1
        self._request_id %= 0x10000

        pkg.request_id = pid = self._request_id
        if priv_proto:
            pkg.msgflags = b'\x03'
            pkg.encrypt(priv_proto, priv_key)
            msg = pkg.encode_auth(auth_proto, auth_key)
        elif auth_proto:
            pkg.msgflags = b'\x01'
            msg = pkg.encode_auth(auth_proto, auth_key)
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

        res = fut.result()
        if priv_proto:
            res.decrypt(priv_proto, priv_key)

        _, _, pdu = res.msgdata
        pdu_id, _, error_status, error_index, vbs = pdu
        if pdu_id == _REPORT_PDU_ID:
            for oid, _, _ in vbs:
                e = _REPORT_OID_EXCEPTIONS.get(oid)
                if e:
                    raise Exception(e)
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

        return vbs

    async def send_encrypted(
            self, pkg, auth_proto, auth_key, priv_proto, priv_key):
        for timeout in (20, 10, 10):
            try:
                res = await self._send_encrypted(
                    pkg, auth_proto, auth_key, priv_proto, priv_key, timeout)
            except SnmpTimeoutError:
                pass
            except Exception as e:
                raise e
            else:
                break
        else:
            raise SnmpTimeoutError
        return res
