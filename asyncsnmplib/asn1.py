# This file is part of Python-ASN1. Python-ASN1 is free software that is
# made available under the MIT license. Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-ASN1 is copyright (c) 2007-2016 by the Python-ASN1 authors.

import enum
from contextlib import contextmanager
from typing import Any, Iterator, List, NamedTuple, Optional, Tuple, Union, \
    cast


class Number(enum.IntEnum):
    EndOfContents = 0x00
    Boolean = 0x01
    Integer = 0x02
    BitString = 0x03
    OctetString = 0x04
    Null = 0x05
    ObjectIdentifier = 0x06
    ObjectDescription = 0x07
    Enumerated = 0x0A
    UTF8String = 0x0C
    Sequence = 0x10
    Set = 0x11
    PrintableString = 0x13
    IA5String = 0x16
    UTCTime = 0x17
    UnicodeString = 0x1E

    IPAddress = 0x40
    Counter32 = 0x41
    Gauge32 = 0x42
    TimeTicks = 0x43
    Opaque = 0x44
    NsapAddress = 0x45
    Counter64 = 0x46
    Uinteger32 = 0x47
    OpaqueFloat = 0x78
    OpaqueDouble = 0x79
    NoSuchObject = 0x80
    NoSuchInstance = 0x81
    EndOfMibView = 0x82


class Type(enum.IntEnum):
    Constructed = 0x20
    Primitive = 0x00


class Class(enum.IntEnum):
    Universal = 0x00
    Application = 0x40
    Context = 0x80
    Private = 0xC0


TNumber = Union[Number, int]
TType = Union[Type, int]
TClass = Union[Class, int]
TOid = Tuple[int, ...]
TValue = Any


class Tag(NamedTuple):
    nr: TNumber
    typ: TType
    cls: TClass


class Error(Exception):
    pass


class Decoder:
    __slots__ = ("m_stack", "m_tag")

    def __init__(self, data: bytes) -> None:
        self.m_stack: List[List] = [[0, data]]
        self.m_tag: Optional[Tag] = None

    def peek(self) -> Tag:
        """This method returns the current ASN.1 tag (i.e. the tag that a
        subsequent `Decoder.read()` call would return) without updating the
        decoding offset. In case no more data is available from the input,
        this method returns ``None`` to signal end-of-file.

        This method is useful if you don't know whether the next tag will be a
        primitive or a constructed tag. Depending on the return value
        of `peek`, you would decide to either issue a `Decoder.read()` in case
        of a primitive type, or an `Decoder.enter()` in case of a constructed
        type.

        Note:
            Because this method does not advance the current offset in the
            input, calling it multiple times in a row will return the same
            value for all calls.

        Returns:
            `Tag`: The current ASN.1 tag.

        Raises:
            `Error`
        """
        if self._end_of_input():
            raise Error("Input is empty.")
        if self.m_tag is None:
            self.m_tag = self._read_tag()
        return self.m_tag

    def read(self, nr: Optional[TNumber] = None) -> Tuple[Tag, Any]:
        """This method decodes one ASN.1 tag from the input and returns it as a
        ``(tag, value)`` tuple. ``tag`` is a 3-tuple ``(nr, typ, cls)``,
        while ``value`` is a Python object representing the ASN.1 value.
        The offset in the input is increased so that the next `Decoder.read()`
        call will return the next tag. In case no more data is available from
        the input, this method returns ``None`` to signal end-of-file.

        Returns:
            `Tag`, value: The current ASN.1 tag and its value.

        Raises:
            `Error`
        """
        if self._end_of_input():
            raise Error("Input is empty.")
        tag = self.peek()
        length = self._read_length()
        if nr is None:
            nr = tag.nr | tag.cls
        value = self._read_value(nr, length)
        self.m_tag = None
        return tag, value

    def eof(self) -> bool:
        """Return True if we are at the end of input.

        Returns:
            bool: True if all input has been decoded, and False otherwise.
        """
        return self._end_of_input()

    @contextmanager
    def enter(self) -> Iterator[None]:
        """This method enters the constructed type that is at the current
        decoding offset.

        Note:
            It is an error to call `Decoder.enter()` if the to be decoded ASN.1
            tag is not of a constructed type.

        Returns:
            None
        """
        tag = self.peek()
        if tag.typ != Type.Constructed:
            raise Error("Cannot enter a non-constructed tag.")
        length = self._read_length()
        bytes_data = self._read_bytes(length)
        self.m_stack.append([0, bytes_data])
        self.m_tag = None

        yield

        if len(self.m_stack) == 1:
            raise Error("Tag stack is empty.")
        del self.m_stack[-1]
        self.m_tag = None

    def _read_tag(self) -> Tag:
        """Read a tag from the input."""
        byte = self._read_byte()
        cls = byte & 0xC0
        typ = byte & 0x20
        nr = byte & 0x1F
        if nr == 0x1F:  # Long form of tag encoding
            nr = 0
            while True:
                byte = self._read_byte()
                nr = (nr << 7) | (byte & 0x7F)
                if not byte & 0x80:
                    break
        return Tag(nr=nr, typ=typ, cls=cls)

    def _read_length(self) -> int:
        """Read a length from the input."""
        byte = self._read_byte()
        if byte & 0x80:
            count = byte & 0x7F
            if count == 0x7F:
                raise Error("ASN1 syntax error")
            bytes_data = self._read_bytes(count)
            length = 0
            for byte in bytes_data:
                length = (length << 8) | int(byte)
            try:
                length = int(length)
            except OverflowError:
                pass
        else:
            length = byte
        return length

    def _read_value(self, nr: TNumber, length: int) -> Any:
        """Read a value from the input."""
        bytes_data = self._read_bytes(length)
        if nr == Number.Boolean:
            return self._decode_boolean(bytes_data)
        elif nr in (
            Number.Integer,
            Number.Enumerated,
            Number.TimeTicks,
            Number.Gauge32,
            Number.Counter32,
            Number.Counter64,
        ):
            return self._decode_integer(bytes_data)
        elif nr == Number.Null:
            return self._decode_null(bytes_data)
        elif nr == Number.ObjectIdentifier:
            return self._decode_object_identifier(bytes_data)
        elif nr in (
                Number.EndOfMibView,
                Number.NoSuchObject,
                Number.NoSuchInstance):
            return None
        return bytes_data

    def _read_byte(self) -> int:
        """Return the next input byte, or raise an error on end-of-input."""
        index, input_data = self.m_stack[-1]
        try:
            byte: int = input_data[index]
        except IndexError:
            raise Error("Premature end of input.")
        self.m_stack[-1][0] += 1
        return byte

    def _read_bytes(self, count: int) -> bytes:
        """Return the next ``count`` bytes of input. Raise error on
        end-of-input."""
        index, input_data = self.m_stack[-1]
        bytes_data: bytes = input_data[index: index + count]
        if len(bytes_data) != count:
            raise Error("Premature end of input.")
        self.m_stack[-1][0] += count
        return bytes_data

    def _end_of_input(self) -> bool:
        """Return True if we are at the end of input."""
        index, input_data = self.m_stack[-1]
        assert not index > len(input_data)
        return cast(int, index) == len(input_data)

    @staticmethod
    def _decode_boolean(bytes_data: bytes) -> bool:
        if len(bytes_data) != 1:
            raise Error("ASN1 syntax error")
        return not bytes_data[0] == 0

    @staticmethod
    def _decode_integer(bytes_data: bytes) -> int:
        values = [int(b) for b in bytes_data]
        negative = values[0] & 0x80
        if negative:
            # make positive by taking two's complement
            for i in range(len(values)):
                values[i] = 0xFF - values[i]
            for i in range(len(values) - 1, -1, -1):
                values[i] += 1
                if values[i] <= 0xFF:
                    break
                assert i > 0
                values[i] = 0x00
        value = 0
        for val in values:
            value = (value << 8) | val
        if negative:
            value = -value
        try:
            value = int(value)
        except OverflowError:
            pass
        return value

    @staticmethod
    def _decode_null(bytes_data: bytes) -> None:
        if len(bytes_data) != 0:
            raise Error("ASN1 syntax error")

    @staticmethod
    def _decode_object_identifier(bytes_data: bytes) -> TOid:
        result: List[int] = []
        value: int = 0
        for i in range(len(bytes_data)):
            byte = int(bytes_data[i])
            if value == 0 and byte == 0x80:
                raise Error("ASN1 syntax error")
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                result.append(value)
                value = 0
        if len(result) == 0 or result[0] > 1599:
            raise Error("ASN1 syntax error")
        result = [result[0] // 40, result[0] % 40] + result[1:]
        # return '.'.join(str(x) for x in result)
        return tuple(result)
