import asyncio
import logging
from typing import Any
from . import exceptions
from .package import Package


_ERROR_STATUS_TO_EXCEPTION = {
    1: exceptions.SnmpErrorTooBig,
    2: exceptions.SnmpErrorNoSuchName,
    3: exceptions.SnmpErrorBadValue,
    4: exceptions.SnmpErrorReadOnly,
    5: exceptions.SnmpErrorGenErr,
    6: exceptions.SnmpErrorNoAccess,
    7: exceptions.SnmpErrorWrongType,
    8: exceptions.SnmpErrorWrongLength,
    9: exceptions.SnmpErrorWrongEncoding,
    10: exceptions.SnmpErrorWrongValue,
    11: exceptions.SnmpErrorNoCreation,
    12: exceptions.SnmpErrorInconsistentValue,
    13: exceptions.SnmpErrorResourceUnavailable,
    14: exceptions.SnmpErrorCommitFailed,
    15: exceptions.SnmpErrorUndoFailed,
    16: exceptions.SnmpErrorAuthorizationError,
    17: exceptions.SnmpErrorNotWritable,
    18: exceptions.SnmpErrorInconsistentName,
}

DEFAULT_TIMEOUTS = (20, 10, 10)


class SnmpProtocol(asyncio.DatagramProtocol):
    __slots__ = (
        'loop', 'target', 'transport', 'requests', '_request_id', '_timeouts')

    def __init__(self, target, timeouts: tuple[int, ...] = DEFAULT_TIMEOUTS):
        self.loop = asyncio.get_running_loop()
        self.target = target
        self.requests = {}
        self._request_id = 0
        self._timeouts = timeouts

    def connection_made(self, transport):
        self.transport = transport

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
                self.requests[pid].set_exception(exceptions.SnmpDecodeError)
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
                exception = None
                if pkg.error_status:  # also exclude None for trap-pdu
                    oid = None
                    if pkg.error_index:  # also exclude None for trap-pdu
                        oidtuple = \
                            pkg.variable_bindings[pkg.error_index - 1][0]
                        oid = '.'.join(map(str, oidtuple))
                    exception = _ERROR_STATUS_TO_EXCEPTION[pkg.error_status](
                        oid
                    )
                try:
                    if exception:
                        self.requests[pid].set_exception(exception)
                    else:
                        self.requests[pid].set_result(pkg.variable_bindings)
                except asyncio.InvalidStateError:
                    del self.requests[pid]
                    logging.error(
                        self._log_with_suffix('Package future already done'))

    def _log_with_suffix(self, msg):
        addr = self.target[0]
        return f'{msg} (source ip: {addr})'

    async def _send(self, pkg, timeout=10):
        self._request_id += 1
        self._request_id %= 0x10000

        pkg.request_id = self._request_id

        pid = pkg.request_id
        fut = self.requests[pid] = self.loop.create_future()
        fut.add_done_callback(
            lambda _: self.requests.pop(pid) if pid in self.requests else None)

        self.transport.sendto(pkg.encode(), self.target)
        done, _ = await asyncio.wait((fut, ), timeout=timeout)
        if not done:
            fut.cancel()
            logging.warning(self._log_with_suffix(
                f'Package pid {pid} timed out after {timeout} seconds'))
            raise exceptions.SnmpTimeoutError
        return fut.result()

    async def send(self, pkg):
        for timeout in self._timeouts:
            try:
                res = await self._send(pkg, timeout)
            except exceptions.SnmpTimeoutError:
                pass
            else:
                break
        else:
            raise exceptions.SnmpTimeoutError
        return res
