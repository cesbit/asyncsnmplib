import asyncio
import logging
from ..exceptions import SnmpTimeoutError
from ..protocol import SnmpProtocol, _ERROR_STATUS_TO_EXCEPTION
from .package import Package


class SnmpV3Protocol(SnmpProtocol):

    def datagram_received(self, data, *args):
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
                self.requests[pid].set_result(pkg)

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
        _, error_status, error_index, vbs = pdu

        if error_status != 0:
            oid = None
            if error_index != 0:
                oid = vbs[error_index - 1][0]
            exception = _ERROR_STATUS_TO_EXCEPTION[error_status](oid)
            raise exception

        return vbs

    async def send_encrypted(
            self, pkg, auth_proto, auth_key, priv_proto, priv_key):
        for timeout in (5, 10, 20):
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
