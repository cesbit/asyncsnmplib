from .asn1 import Decoder, Encoder, Number


class Package:
    pdu_id = None
    version = None
    community = None
    pdu = None

    def __init__(self):
        self.request_id = None
        self.error_status = None
        self.error_index = None
        self.variable_bindings = []

    def encode(self):
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
