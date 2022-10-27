from .asn1 import Class, Number


class PDU:
    pdu_id = None
    request_id = None
    non_repeaters = 0
    max_repetitions = 0
    variable_bindings = []

    def encode(self, encoder):
        with encoder.enter(self.pdu_id, Class.Context):
            encoder.write(self.request_id, Number.Integer)
            encoder.write(self.non_repeaters, Number.Integer)
            encoder.write(self.max_repetitions, Number.Integer)

            with encoder.enter(Number.Sequence):
                for oid in self.variable_bindings:
                    with encoder.enter(Number.Sequence):
                        encoder.write(oid, Number.ObjectIdentifier)
                        encoder.write(None)


class SnmpGet(PDU):
    pdu_id = 0

    def __init__(self, request_id, variable_bindings):
        self.request_id = request_id
        self.variable_bindings = variable_bindings


class SnmpGetNext(PDU):
    pdu_id = 1

    def __init__(self, request_id, variable_bindings):
        self.request_id = request_id
        self.variable_bindings = variable_bindings


class SnmpGetBulk(PDU):
    pdu_id = 5

    def __init__(
            self,
            request_id,
            variable_bindings,
            non_repeaters=0,
            max_repetitions=20):
        self.request_id = request_id
        self.non_repeaters = non_repeaters
        self.max_repetitions = max_repetitions
        self.variable_bindings = variable_bindings
