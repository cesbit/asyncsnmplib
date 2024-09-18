
import asyncio
import logging
from typing import Optional, Any
from .protocol import SnmpProtocol, Package
from .asn1 import Decoder
from .mib.mib_index import MIB_INDEX

# TODOK
# GENERIC_TRAP = {
#     v['value']: {**v, 'name': k}
#     for k, v in MIB_INDEX['RFC-1215'][None].items()
# }


def on_package(data):
    decoder = Decoder(data)
    with decoder.enter():
        decoder.read()  # version
        decoder.read()  # community

        with decoder.enter():
            tag, value = decoder.read()
            # print(value)
            tag, value = decoder.read()
            # print(value)
            tag, value = decoder.read()
            generic_trap_id = value
            # print(value)
            tag, value = decoder.read()
            # print(value)
            tag, value = decoder.read()
            # print(value)

            variable_bindings = []
            with decoder.enter():
                while not decoder.eof():
                    with decoder.enter():
                        _, oid = decoder.read()
                        tag, value = decoder.read()
                        variable_bindings.append((oid, tag, value))

            # print(GENERIC_TRAP[generic_trap_id])
            print(variable_bindings)


class SnmpTrapProtocol(SnmpProtocol):

    def datagram_received(self, data: bytes, addr: Any):
        # NOTE on typing
        # https://docs.python.org/3/library/asyncio-protocol.html
        # addr is the address of the peer sending the data;
        # the exact format depends on the transport.
        pkg = Package()
        try:
            pkg.decode(data)
        except Exception:
            # TODO SnmpDecodeError?
            logging.error(
                self._log_with_suffix('Failed to decode package'))
        else:
            logging.debug('Trap message received')
            for oid, tag, value in pkg.variable_bindings:
                mib_object = MIB_INDEX.get(oid[:-1])
                if mib_object is None:
                    # only accept oids from loaded mibs
                    continue
                logging.info(
                    f'oid: {oid} name: {mib_object["name"]} value: {value}'
                )
                # TODO some values need oid lookup for the value, do here or in
                # outside processor


class SnmpTrap:
    def __init__(
            self,
            host: str = '0.0.0.0',
            port: int = 162,
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

    async def listen(self):
        transport, protocol = await self._loop.create_datagram_endpoint(
            lambda: SnmpTrapProtocol((None, None)),
            local_addr=(self.host, self.port),
        )
        self._protocol = protocol
        self._transport = transport

    def close(self):
        if self._transport is not None and not self._transport.is_closing():
            self._transport.close()
        self._protocol = None
        self._transport = None
