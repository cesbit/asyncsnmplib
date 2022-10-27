from .asn1 import Decoder, Encoder, Number


class Package:
    pdu_id = None
    version = None
    community = None
    pdu = None

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
                _, request_id = decoder.read()
                _, error_status = decoder.read()
                _, error_index = decoder.read()

                with decoder.enter():
                    variable_bindings = []
                    while not decoder.eof():
                        with decoder.enter():
                            _, oid = decoder.read()
                            tag, value = decoder.read()
                            variable_bindings.append((oid, tag, value))

        self.request_id = request_id
        self.error_status = error_status
        self.error_index = error_index
        self.variable_bindings = variable_bindings


class SnmpMessage(Package):

    @classmethod
    def make(cls, version, community, pdu):
        pkg = cls()
        pkg.version = version
        pkg.community = community
        pkg.pdu = pdu
        return pkg
