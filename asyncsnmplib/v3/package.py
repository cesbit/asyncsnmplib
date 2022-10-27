from ..asn1 import Decoder, Encoder, Number


def _encode_scopedpdu(encoder, contextengineid, contextname, pdu):
    with encoder.enter(Number.Sequence):
        encoder.write(contextengineid, Number.OctetString)
        encoder.write(contextname, Number.OctetString)
        pdu.encode(encoder)


def _decode_scopedpdu(decoder):
    with decoder.enter():
        _, contextengineid = decoder.read()
        _, contextname = decoder.read()

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
    return [
        contextengineid,
        contextname,
        [
            request_id,
            error_status,
            error_index,
            variable_bindings
        ]
    ]


def _encode_msgsecurityparameters(orig):
    encoder = Encoder()
    with encoder.enter(Number.Sequence):
        encoder.write(orig[0], Number.OctetString)
        encoder.write(orig[1], Number.Integer)
        encoder.write(orig[2], Number.Integer)
        encoder.write(orig[3], Number.OctetString)
        encoder.write(orig[4], Number.OctetString)
        encoder.write(orig[5], Number.OctetString)
    return encoder.output()


def _decode_msgsecurityparameters(data):
    decoder = Decoder(data)
    with decoder.enter():
        _, authoritative_engine_id = decoder.read()
        _, authoritative_engine_boots = decoder.read()
        _, authoritative_engine_time = decoder.read()
        _, username = decoder.read()
        _, authentication_parameters = decoder.read()
        _, privacy_parameters = decoder.read()
    return [
        authoritative_engine_id,
        authoritative_engine_boots,
        authoritative_engine_time,
        username,
        authentication_parameters,
        privacy_parameters
    ]


class Package:

    pdu_id = None
    request_id = None
    version = None
    msgmaxsize = None
    msgflags = None
    msgsecuritymodel = None
    msgsecurityparameters = None
    pdu = None

    def encode(self):
        encoder = Encoder()
        with encoder.enter(Number.Sequence):
            encoder.write(self.version, Number.Integer)

            with encoder.enter(Number.Sequence):
                encoder.write(self.request_id, Number.Integer)
                encoder.write(self.msgmaxsize, Number.Integer)
                encoder.write(self.msgflags, Number.OctetString)
                encoder.write(self.msgsecuritymodel, Number.Integer)

            params = _encode_msgsecurityparameters(self.msgsecurityparameters)
            encoder.write(params, Number.OctetString)
            if self.msgflags == b'\x03':
                encoder.write(self.msgdata, Number.OctetString)
            else:
                _encode_scopedpdu(encoder, b'', b'', self.pdu)

        return encoder.output()

    def decode(self, data):
        decoder = Decoder(data)
        with decoder.enter():
            _, version = decoder.read()

            with decoder.enter():
                _, msgid = decoder.read()
                _, msgmaxsize = decoder.read()
                _, msgflags = decoder.read()
                _, msgsecuritymodel = decoder.read()

            _, msgsecurityparameters = decoder.read()
            params = _decode_msgsecurityparameters(msgsecurityparameters)

            if msgflags == b'\x03':
                _, msgdata = decoder.read()
            else:
                msgdata = _decode_scopedpdu(decoder)

        self.request_id = msgid
        self.version = version
        self.msgmaxsize = msgmaxsize
        self.msgflags = msgflags
        self.msgsecuritymodel = msgsecuritymodel
        self.msgsecurityparameters = params
        self.msgdata = msgdata

    def encrypt(self, proto, key):
        encoder_2 = Encoder()
        _encode_scopedpdu(encoder_2, b'', b'', self.pdu)
        encoded = encoder_2.output()
        self.msgdata = proto.encrypt(key, encoded, self.msgsecurityparameters)

    def decrypt(self, proto, key):
        pdu = proto.decrypt(key, self.msgdata, self.msgsecurityparameters)
        decoder = Decoder(pdu)
        self.msgdata = _decode_scopedpdu(decoder)

    def encode_auth(self, proto, key):
        encoded = self.encode()
        return proto.auth(key, encoded)


class SnmpV3Message(Package):

    @classmethod
    def make(cls, pdu, msgsecurityparameters):
        pkg = cls()
        pkg.version = 3
        pkg.msgflags = b'\x00'
        pkg.msgmaxsize = 2 ** 16
        pkg.msgsecuritymodel = 3
        pkg.msgsecurityparameters = msgsecurityparameters
        pkg.pdu = pdu
        return pkg
