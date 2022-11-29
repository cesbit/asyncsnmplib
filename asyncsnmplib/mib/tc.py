MIB_TEXTUAL_CONVENTIONS = {
    'RFC1155-SMI': {
        'Counter': {'tp': 'INTEGER'},
        'Gauge': {'tp': 'INTEGER'},
        'TimeTicks': {'tp': 'CUSTOM', 'func': 'TimeTicks'},
        'Opaque': {'tp': 'OCTET STRING'},
        'IpAddress': {'tp': 'CUSTOM', 'func': 'IpAddress'},
        'NetworkAddress': {'tp': 'CUSTOM', 'func': 'IpAddress'},
    },
    'RFC1213-MIB': {
        'DisplayString': {'tp': 'CUSTOM', 'func': 'DisplayString'},
        'PhysAddress': {'tp': 'CUSTOM', 'func': 'PhysAddress'},
    },
    'SNMPv2-SMI': {
        'Counter32': {'tp': 'INTEGER'},
        'Gauge32': {'tp': 'INTEGER'},
        'Integer32': {'tp': 'INTEGER'},
        'Unsigned32': {'tp': 'INTEGER'},
        'Counter64': {'tp': 'INTEGER'},
        'TimeTicks': {'tp': 'CUSTOM', 'func': 'TimeTicks'},
        'Opaque': {'tp': 'OCTET STRING'},
        'IpAddress': {'tp': 'CUSTOM', 'func': 'IpAddress'},
    },
    'SNMPv2-TC': {
        'DateAndTime': {'tp': 'CUSTOM', 'func': 'DateAndTime'},
        'DisplayString': {'tp': 'CUSTOM', 'func': 'DisplayString'},
        'MacAddress': {'tp': 'CUSTOM', 'func': 'MacAddress'},
        'PhysAddress': {'tp': 'CUSTOM', 'func': 'PhysAddress'},
        'TruthValue': {'tp': 'CUSTOM', 'func': 'TruthValue'},
    },

    'HOST-RESOURCES-MIB': {
        'InternationalDisplayString': {
            'tp': 'CUSTOM', 'func': 'DisplayString'},
    },
    'SNMP-FRAMEWORK-MIB': {
        'SnmpAdminString': {'tp': 'CUSTOM', 'func': 'DisplayString'},
    },
}
