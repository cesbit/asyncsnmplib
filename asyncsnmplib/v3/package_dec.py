# type: ignore
from Crypto.Util.asn1 import DerSequence, DerObjectId
# from .package import Package


def _decode_scopedpdu(data):
    s2 = DerSequence()

    # TODO
    try:
        contextengineid, contextname, data = s2.decode(data)
    except ValueError:
        contextengineid, contextname, data = s2._seq

    tag_octet = data[0]
    pdu_id = tag_octet - 0xA0

    s4 = DerSequence(implicit=pdu_id)
    s4.decode(data)
    request_id, error_status, error_index, variable_bindings_ = s4

    variable_bindings = []
    s = DerSequence()
    for vb in s.decode(variable_bindings_):
        s = DerSequence()
        oid, v = s.decode(vb)
        oid = DerObjectId().decode(oid)
        oid = tuple(map(int, oid.value.split('.')))
        variable_bindings.append((oid, None, v))

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


def _decode_msgsecurityparameters(data):
    seq_der = DerSequence()
    seq_der.decode(data)
    return [
        seq_der[0][2:],
        seq_der[1],
        seq_der[2],
        seq_der[3][2:],
        seq_der[4][2:],
        seq_der[5][2:],
    ]


class Decoder:
    def decode(self, data):
        s = DerSequence()
        version, msgglobaldata, msgsecurityparameters, msgdata = s.decode(data)

        s1 = DerSequence()
        msgid, msgmaxsize, msgflags, msgsecuritymodel = \
            s1.decode(msgglobaldata)

        self.request_id = msgid
        self.version = version
        self.msgmaxsize = msgmaxsize
        self.msgflags = msgflags[2:]
        self.msgsecuritymodel = msgsecuritymodel
        self.msgsecurityparameters = \
            _decode_msgsecurityparameters(msgsecurityparameters[2:])
        self.msgdata = msgdata[2:] if self.msgflags == b'\x03' else \
            _decode_scopedpdu(msgdata)

    def decrypt(self, proto, key):
        data = proto.decrypt(key, self.msgdata[2:], self.msgsecurityparameters)
        self.msgdata = _decode_scopedpdu(data)
