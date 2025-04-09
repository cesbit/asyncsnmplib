import logging
import os
from Crypto.Util.asn1 import (
    DerSequence, DerOctetString, DerObjectId, DerObject, DerNull, DerInteger,
    DerBoolean)
from typing import Any
from .asn1 import Number

MAX_CHARS_PKG = None if os.getenv('LOG_LEVEL', '').lower() == 'DEBUG' else 80


class PDU:
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
                DerSequence([
                    DerObjectId('.'.join(map(str, oid))),
                    DerNull()
                ])
                for oid in self.variable_bindings
            ]),
        ], implicit=self.pdu_id)
        return s.encode()

    def decode(self, der_encoded):
        tag_octet = der_encoded[0]
        pdu_id = tag_octet - 0xA0

        try:
            s: Any = DerSequence(implicit=pdu_id).decode(der_encoded)
            request_id, error_status, error_index, vbs = s
        except Exception as e:
            msg = str(e) or type(e).__name__
            vbsstr = der_encoded.hex(' ')[:MAX_CHARS_PKG]
            logging.warning(f'Failed to parse PDU: {msg} {vbsstr}')
            raise

        self.pdu_id = pdu_id
        # it is important to set request_id early so that that the
        # future/handle can be found to set the exception which happen
        # after this
        self.request_id = request_id
        self.error_status = error_status
        self.error_index = error_index
        self.variable_bindings = variable_bindings = []

        try:
            s: Any = DerSequence().decode(vbs)
        except Exception as e:
            msg = str(e) or type(e).__name__
            vbsstr = vbs.hex(' ')[:MAX_CHARS_PKG]
            logging.warning(f'Failed to parse VarBindList: {msg} {vbsstr}')
            raise
        for vb in s:
            try:
                s = DerSequence()
                oid, v = s.decode(vb)
                oid = DerObjectId().decode(oid)
                oid = tuple(map(int, oid.value.split('.')))
            except Exception as e:
                msg = str(e) or type(e).__name__
                vbsstr = vb.hex(' ')[:MAX_CHARS_PKG]
                logging.warning(f'Failed to parse VarBind: {msg} {vbsstr}')
                raise
            if isinstance(v, int):
                # DER INTEGERs are already decoded
                tag_octet = Number.Integer
                variable_bindings.append((oid, tag_octet, v))
                continue
            try:
                o: Any = DerObject().decode(v)
                tag_octet = o._tag_octet
                if tag_octet == Number.Boolean:
                    v = DerBoolean().decode(v).value
                elif tag_octet == Number.ObjectIdentifier:
                    o = DerObjectId().decode(v).value
                    v = tuple(map(int, o.split('.')))
                elif tag_octet in (
                    Number.Enumerated,
                    Number.TimeTicks,
                    Number.Gauge32,
                    Number.Counter32,
                    Number.Counter64,
                ):
                    i: Any = DerInteger()
                    i._tag_octet = tag_octet
                    v = i.decode(v).value
                elif tag_octet in (
                    Number.Null,
                    Number.EndOfMibView,
                    Number.NoSuchObject,
                    Number.NoSuchInstance
                ):
                    v = None
                else:
                    v = o.payload
            except Exception as e:
                msg = str(e) or type(e).__name__
                vbsstr = v.hex(' ')[:MAX_CHARS_PKG]
                logging.warning(f'Failed to parse Value: {msg} {vbsstr}')
                raise
            variable_bindings.append((oid, tag_octet, v))


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
            self.data,  # type: ignore
            # PDU is not realy a DerObject but with the same interface as
            # DerObject.encode
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
