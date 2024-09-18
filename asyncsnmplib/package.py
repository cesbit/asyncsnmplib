from typing import Optional, Tuple, List
from .asn1 import Decoder, Encoder, Number, Tag, TOid, TValue


class Package:
    pdu_id = None
    version = None
    community = None
    pdu = None

    def __init__(self):
        self.request_id: Optional[int] = None
        self.error_status: Optional[int] = None
        self.error_index: Optional[int] = None
        self.variable_bindings: List[Tuple[TOid, Tag, TValue]] = []

    def encode(self):
        assert self.pdu is not None
        encoder = Encoder()

        with encoder.enter(Number.Sequence):
            encoder.write(self.version, Number.Integer)
            encoder.write(self.community, Number.OctetString)

            self.pdu.request_id = self.request_id
            self.pdu.encode(encoder)

        return encoder.output()

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

    @classmethod
    def make(cls, version, community, pdu):
        pkg = cls()
        pkg.version = version
        pkg.community = community
        pkg.pdu = pdu
        return pkg
