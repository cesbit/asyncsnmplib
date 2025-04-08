from Crypto.Util.asn1 import (
    DerSequence, DerOctetString, DerObjectId, DerObject, DerNull)


class PDU(DerObject):
    pdu_id = None

    def __init__(
            self,
            request_id=0,
            error_status=0,
            error_index=0,
            variable_bindings=[]):
        self.request_id = request_id
        self.error_status = error_status
        self.error_index = error_index
        self.variable_bindings = variable_bindings

    def encode(self):
        s = DerSequence([
            self.request_id,
            self.error_status,
            self.error_index,
            DerSequence([
                DerSequence([DerObjectId('.'.join(map(str, oid))), DerNull()])
                for oid in self.variable_bindings
            ]),
        ], implicit=self.pdu_id)
        return s.encode()


class ScopedPDU:
    data: PDU
    contextengineid: bytes = b''
    contextname: bytes = b''

    def __init__(
        self,
        data: PDU,
        contextengineid: bytes = b'',
        contextname: bytes = b'',
    ):
        self.data = data
        self.contextengineid = contextengineid
        self.contextname = contextname

    def encode(self):
        s = DerSequence([
            DerOctetString(self.contextengineid),
            DerOctetString(self.contextname),
            self.data,
        ])
        return s.encode()


class SnmpGet(PDU):
    pdu_id = 0


class SnmpGetNext(PDU):
    pdu_id = 1


class SnmpGetBulk(PDU):
    pdu_id = 5

    def __init__(
            self,
            request_id=0,
            non_repeaters=0,
            max_repetitions=20,
            variable_bindings=[]):
        self.request_id = request_id
        self.non_repeaters = non_repeaters
        self.max_repetitions = max_repetitions
        self.variable_bindings = variable_bindings

    def encode(self):
        s = DerSequence([
            self.request_id,
            self.non_repeaters,
            self.max_repetitions,
            DerSequence([
                DerSequence([DerObjectId('.'.join(map(str, oid))), DerNull()])
                for oid in self.variable_bindings
            ]),
        ], implicit=self.pdu_id)
        return s.encode()
