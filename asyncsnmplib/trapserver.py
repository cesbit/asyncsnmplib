
import asyncio
import logging
from .protocol import SnmpProtocol, Package
from .asn1 import Decoder
from asyncsnmplib.mib.mib_index import MIB_INDEX

# TODOK
# GENERIC_TRAP = {
#     v['value']: {**v, 'name': k} for k, v in MIB_INDEX['RFC-1215'][None].items()
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

    def datagram_received(self, data: bytes, *args):
        pkg = Package()
        try:
            pkg.decode(data)
        except Exception:
            # TODO SnmpDecodeError?
            logging.error(
                self._log_with_suffix('Failed to decode package'))
        else:
            # print(pkg.variable_bindings)
            # for oid, tag, value in pkg.variable_bindings:
            #     print(oid, MIB_INDEX.get(oid[:-1])['name'])

            for oid, tag, value in pkg.variable_bindings[1:]:
                print(MIB_INDEX.get(oid[:-1])['name'], MIB_INDEX.get(value[:-1])['name'])


class SnmpTrap:
    def __init__(self, host='0.0.0.0', port=162, community='public', max_rows=10000):
        self._loop = asyncio.get_event_loop()
        self._protocol = None
        self._transport = None
        self.host = host
        self.port = port
        self.community = community
        self.max_rows = max_rows

    def start(self):
        transport, protocol = self._loop.run_until_complete(
            self._loop.create_datagram_endpoint(
                lambda: SnmpTrapProtocol((None, None)),
                local_addr=(self.host, self.port),
            )
        )
        self._protocol = protocol
        self._transport = transport
        self._loop.run_forever()
