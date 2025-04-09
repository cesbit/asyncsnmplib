from Crypto.Util.asn1 import DerSequence, DerOctetString
from typing import Any
from ..pdu import PDU


def _decode_scopedpdu(data):
    s2 = DerSequence()
    contextengineid, contextname, data = s2.decode(data)

    pdu = PDU()
    pdu.decode(data)

    return [
        contextengineid,
        contextname,
        [
            pdu.pdu_id,
            pdu.request_id,
            pdu.error_status,
            pdu.error_index,
            pdu.variable_bindings
        ]
    ]


def _decode_msgsecurityparameters(data):
    seq_der: Any = DerSequence()
    seq_der.decode(data)
    return [
        seq_der[0][2:],
        seq_der[1],
        seq_der[2],
        seq_der[3][2:],
        seq_der[4][2:],
        seq_der[5][2:],
    ]


class Package:

    request_id: int
    version: int
    msgmaxsize: int
    msgflags: bytes
    msgsecuritymodel: int
    msgsecurityparameters: list
    msgdata: Any

    def decode(self, data):
        s: Any = DerSequence()
        version, msgglobaldata, msgsecurityparameters, msgdata = s.decode(data)

        s1: Any = DerSequence()
        msgid, msgmaxsize, msgflags, msgsecuritymodel = \
            s1.decode(msgglobaldata)

        self.request_id = msgid
        self.version = version
        self.msgmaxsize = msgmaxsize
        self.msgflags = msgflags[2:]
        self.msgsecuritymodel = msgsecuritymodel
        self.msgsecurityparameters = \
            _decode_msgsecurityparameters(msgsecurityparameters[2:])
        self.msgdata = msgdata if self.msgflags == b'\x03' else \
            _decode_scopedpdu(msgdata)

    def decrypt(self, proto, key):
        v = DerOctetString().decode(self.msgdata).payload
        data = proto.decrypt(key, v, self.msgsecurityparameters)
        self.msgdata = _decode_scopedpdu(data)
