from Crypto.Util.asn1 import DerSequence, DerOctetString, DerObject


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


class Package:

    request_id: int
    version: int
    msgmaxsize: int
    msgflags: bytes
    msgsecuritymodel: int
    msgsecurityparameters: list
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

    def encrypt(self, proto, key):
        encoded = self.pdu.encode()
        encryped = proto.encrypt(key, encoded, self.msgsecurityparameters)
        self.pdu = DerOctetString(encryped)

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
