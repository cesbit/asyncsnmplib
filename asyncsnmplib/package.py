from Crypto.Util.asn1 import DerSequence, DerOctetString
from .asn1 import Decoder, Tag, TOid, TValue
from .pdu import PDU


class Package:
    version: int
    community: bytes
    pdu: PDU

    def __init__(self):
        self.request_id: int | None = None
        self.error_status: int | None = None
        self.error_index: int | None = None
        self.variable_bindings: list[tuple[TOid, Tag, TValue]] = []

    def encode(self):
        assert self.pdu is not None
        assert self.request_id is not None
        self.pdu.request_id = self.request_id

        encoder = DerSequence([
            self.version,
            DerOctetString(self.community),
            self.pdu
        ])
        return encoder.encode()

    def decode(self, data):
        decoder = Decoder(data)
        with decoder.enter():
            decoder.read()  # version
            decoder.read()  # community

            with decoder.enter():
                _, self.request_id = decoder.read()
                _, self.error_status = decoder.read()
                _, self.error_index = decoder.read()

                with decoder.enter():
                    while not decoder.eof():
                        with decoder.enter():
                            _, oid = decoder.read()
                            tag, value = decoder.read()
                            self.variable_bindings.append((oid, tag, value))


class SnmpMessage(Package):
    request_id: int | None = None

    @classmethod
    def make(cls, version, community, pdu):
        pkg = cls()
        pkg.version = version
        pkg.community = community
        pkg.pdu = pdu
        return pkg
