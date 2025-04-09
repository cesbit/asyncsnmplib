from Crypto.Util.asn1 import DerSequence, DerOctetString
from typing import Optional, Tuple, List
from .asn1 import Tag, TOid, TValue
from .pdu import PDU


class Package:
    version: int
    community: bytes
    pdu: PDU

    def __init__(self):
        self.request_id: Optional[int] = None
        self.error_status: Optional[int] = None
        self.error_index: Optional[int] = None
        self.variable_bindings: List[Tuple[TOid, Tag, TValue]] = []

    def encode(self):
        assert self.pdu is not None
        assert self.request_id is not None
        self.pdu.request_id = self.request_id

        encoder = DerSequence([
            self.version,
            DerOctetString(self.community),
            self.pdu
        ])
        return encoder.encode()

    def decode(self, data):
        s2 = DerSequence()
        _, _, data = s2.decode(data)

        pdu = PDU()
        try:
            pdu.decode(data)
        except Exception:
            raise
        finally:
            self.request_id = pdu.request_id
            self.error_status = pdu.error_status
            self.error_index = pdu.error_index
            self.variable_bindings = pdu.variable_bindings


class SnmpMessage(Package):
    request_id: Optional[int] = None

    @classmethod
    def make(cls, version, community, pdu):
        pkg = cls()
        pkg.version = version
        pkg.community = community
        pkg.pdu = pdu
        return pkg
