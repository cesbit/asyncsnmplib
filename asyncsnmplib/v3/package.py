from Crypto.Util.asn1 import DerSequence, DerOctetString, DerObject
from ..asn1 import Decoder


def _decode_scopedpdu(decoder):
    with decoder.enter():
        _, contextengineid = decoder.read()
        _, contextname = decoder.read()

        tag = decoder.peek()
        pdu_id = tag.nr
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
            pdu_id,
            request_id,
            error_status,
            error_index,
            variable_bindings
        ]
    ]


def _encode_msgsecurityparameters(orig):
    encoder = DerSequence([
        DerOctetString(orig[0]),
        orig[1],
        orig[2],
        DerOctetString(orig[3]),
        DerOctetString(orig[4]),
        DerOctetString(orig[5]),
    ])
    return encoder.encode()


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

    request_id: int
    version: int
    msgmaxsize: int
    msgflags: bytes
    msgsecuritymodel: int
    msgsecurityparameters: list
    msgdata: list
    pdu: DerObject

    def encode(self):
        params = _encode_msgsecurityparameters(self.msgsecurityparameters)
        encoder = DerSequence([
            self.version,
            DerSequence([
                self.request_id,
                self.msgmaxsize,
                DerOctetString(self.msgflags),
                self.msgsecuritymodel,
            ]),
            DerOctetString(params),
            self.pdu
        ])
        return encoder.encode()

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
        encoded = self.pdu.encode()
        encryped = proto.encrypt(key, encoded, self.msgsecurityparameters)
        self.pdu = DerOctetString(encryped)

    def decrypt(self, proto, key):
        pdu = proto.decrypt(key, self.msgdata, self.msgsecurityparameters)
        decoder = Decoder(pdu)
        self.msgdata = _decode_scopedpdu(decoder)

    def encode_auth(self, proto, key):
        self.msgsecurityparameters[4] = b'\x00' * proto.sz  # type: ignore
        encoded = self.encode()
        auth_key = proto.auth(key, encoded)

        # set auth_key
        self.msgsecurityparameters[4] = auth_key[:proto.sz]  # type: ignore

        # encode again with the auth_key
        encoded = self.encode()
        return encoded


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
