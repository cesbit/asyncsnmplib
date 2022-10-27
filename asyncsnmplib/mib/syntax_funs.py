import ipaddress
import re
import struct
import time

ILLEGAL_CHARS = re.compile('\x00|\n|\r|\t')


def PhysAddress(value):
    '''
    PhysAddress ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "1x:"
    STATUS       current
    DESCRIPTION
            "Represents media- or physical-level addresses."
    SYNTAX       OCTET STRING
    '''
    return ':'.join(map('{:02x}'.format, value))


def MacAddress(value):
    '''
    MacAddress ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "1x:"
    STATUS       current
    DESCRIPTION
            "Represents an 802 MAC address represented in the
            `canonical' order defined by IEEE 802.1a, i.e., as if it
            were transmitted least significant bit first, even though
            802.5 (in contrast to other 802.x protocols) requires MAC
            addresses to be transmitted most significant bit first."
    SYNTAX       OCTET STRING (SIZE (6))
    '''
    return ':'.join(map('{:02x}'.format, value))


def DateAndTime(value):
    '''
    DateAndTime ::= TEXTUAL-CONVENTION
        DISPLAY-HINT "2d-1d-1d,1d:1d:1d.1d,1a1d:1d"
        STATUS       current
        DESCRIPTION
                "A date-time specification.
                field  octets  contents                  range
                -----  ------  --------                  -----
                1      1-2   year                      0..65536
                2       3    month                     1..12
                3       4    day                       1..31
                4       5    hour                      0..23
                5       6    minutes                   0..59
                6       7    seconds                   0..60
                            (use 60 for leap-second)
                7       8    deci-seconds              0..9
                8       9    direction from UTC        '+' / '-'
                9      10    hours from UTC            0..11
                10      11    minutes from UTC          0..59
                For example, Tuesday May 26, 1992 at 1:30:15 PM EDT would be
                displayed as:
                                1992-5-26,13:30:15.0,-4:0
                Note that if only local time is known, then timezone
                information (fields 8-10) is not present."
        SYNTAX       OCTET STRING (SIZE (8 | 11))
    '''
    if len(value) == 11:
        if value[8]:
            offset = -(value[9] * 3600 + value[10] * 60)
        else:
            offset = value[9] * 3600 + value[10] * 60
    elif len(value) == 8:
        offset = 0
    else:
        return None
    timetupl = struct.unpack('>HBBBBB', value[:7]) + (0, 0, -1)
    try:
        return int(time.mktime(timetupl)) + offset
    except Exception:
        return None


def DisplayString(value):
    '''
    DisplayString ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "255a"
    STATUS       current
    DESCRIPTION
            "Represents textual information taken from the NVT ASCII
            character set, as defined in pages 4, 10-11 of RFC 854.
            To summarize RFC 854, the NVT ASCII repertoire specifies:
              - the use of character codes 0-127 (decimal)
              - the graphics characters (32-126) are interpreted as
                US ASCII
              - NUL, LF, CR, BEL, BS, HT, VT and FF have the special
                meanings specified in RFC 854
              - the other 25 codes have no standard interpretation
              - the sequence 'CR LF' means newline
              - the sequence 'CR NUL' means carriage-return
              - an 'LF' not preceded by a 'CR' means moving to the
                same column on the next line.
              - the sequence 'CR x' for any x other than LF or NUL is
                illegal.  (Note that this also means that a string may
                end with either 'CR LF' or 'CR NUL', but not with CR.)
            Any object defined using this syntax may not exceed 255
            characters in length."
    SYNTAX       OCTET STRING (SIZE (0..255))
    '''
    decoded = value.decode('ascii', 'ignore')
    if re.search(ILLEGAL_CHARS, decoded):
        decoded = re.sub(ILLEGAL_CHARS, '', decoded)
    return decoded.rstrip()


def TruthValue(value):
    '''
    TruthValue ::= TEXTUAL-CONVENTION
    STATUS       current
    DESCRIPTION
            "Represents a boolean value."
    SYNTAX       INTEGER { true(1), false(2) }
    '''
    return value == 1


def TimeTicks(value):
    '''
    TimeTicks ::=
        [APPLICATION 3]
            IMPLICIT INTEGER (0..4294967295)

    This application-wide type represents a non-negative integer which
    counts the time in hundredths of a second since some epoch.  When
    object types are defined in the MIB which use this ASN.1 type, the
    description of the object type identifies the reference epoch.
    src: RC1155-SMI
    '''
    # some agents don't follow mib rules and return b'Not Available'
    try:
        return int(value)
    except Exception:
        return None


def IpAddress(octets):
    return '.'.join(map(str, octets))


def Ipv6Address(octets):
    nr = sum(o * (2 ** ((16 - i - 1) * 8)) for i, o in enumerate(octets))
    return str(ipaddress.IPv6Address(nr))


SYNTAX_FUNS = {
    'TimeTicks': TimeTicks,
    'DateAndTime': DateAndTime,
    'DisplayString': DisplayString,
    'MacAddress': MacAddress,
    'PhysAddress': PhysAddress,
    'TruthValue': TruthValue,
    'IpAddress': IpAddress,
    'Ipv6Address': Ipv6Address,
}
