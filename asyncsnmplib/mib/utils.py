from typing import Tuple, Union, List
from ..asn1 import TOid, TValue
from .mib_index import MIB_INDEX
from .syntax_funs import SYNTAX_FUNS


ENUM_UNKNOWN = None

FLAGS_SEPERATOR = ','


def on_octet_string(value: TValue) -> Union[str, None]:
    """
    used as a fallback for OCTET STRING when no formatter is found/defined
    """
    try:
        return value.decode('utf-8')
    except Exception:
        return


def on_integer(value: TValue) -> Union[int, None]:
    if not isinstance(value, int):
        return
    return value


def on_oid_map(oid: TValue) -> Union[str, None]:
    if not isinstance(oid, tuple):
        # some devices don't follow mib's syntax
        # for example ipAddressTable.ipAddressPrefix returns an int in case of
        # old ups firmware version
        # possible solution is to take tag.nr into account while choosing
        # translation func
        return
    # translation.name is always str
    return MIB_INDEX.get(oid, {}).get('name', '.'.join(map(str, oid)))


def on_value_map(value: int, map_: dict) -> Union[str, None]:
    return map_.get(value, ENUM_UNKNOWN)


def on_value_map_b(value: bytes, map_: dict) -> str:
    return FLAGS_SEPERATOR.join(
        v for k, v in map_.items() if value[k // 8] & (1 << k % 8))


def on_syntax(syntax: dict, value: TValue):
    """
    this is point where bytes are converted to right datatype
    """
    if syntax['tp'] == 'CUSTOM':
        return SYNTAX_FUNS[syntax['func']](value)
    elif syntax['tp'] == 'OCTET STRING':
        return on_octet_string(value)
    elif syntax['tp'] == 'OBJECT IDENTIFIER':
        return on_oid_map(value)
    elif syntax['tp'] == 'BITS':
        return on_value_map_b(value, syntax['values'])
    elif syntax['tp'] == 'INTEGER' and syntax.get('values'):
        return on_value_map(value, syntax['values'])
    elif syntax['tp'] == 'INTEGER':
        return on_integer(value)
    else:
        raise Exception(f'Invalid syntax {syntax}')


def on_result(
    base_oid: TOid,
    result: List[Tuple[TOid, TValue]],
) -> Tuple[str, List[dict]]:
    """returns a more compat result (w/o prefixes) and groups formatted
    metrics by base_oid
    """
    base = MIB_INDEX[base_oid]
    base_name = result_name = base['name']
    prefixlen = len(base_oid) + 1

    if base_name.endswith('XEntry'):
        # for SEQUENCE types with AUGMENTS clause remove suffix
        result_name = base_name[:-5]
        base_name = base_name[:-6]
    elif base_name.endswith('Entry'):
        # for SEQUENCE types remove suffix
        base_name = result_name = base_name[:-5]

    table = {}
    for oid, value in result:
        idx = oid[prefixlen:]
        prefix = oid[:prefixlen]
        if prefix not in MIB_INDEX:
            continue
        tp = MIB_INDEX[prefix]['tp']
        if tp != 'OBJECT-TYPE':
            continue
        name = MIB_INDEX[prefix]['name']
        _, _, lastpart = name.partition(base_name)
        name = lastpart or name

        syntax = MIB_INDEX[prefix]['syntax']
        if idx not in table:
            table[idx] = {'name': '.'.join(map(str, idx))}
        try:
            table[idx][name] = on_syntax(syntax, value)
        except Exception as e:
            raise Exception('Something went wrong in the metric processor:'
                            f' {e.__class__.__name__}: {e}')

    return result_name, list(table.values())


def on_result_base(
    base_oid: TOid,
    result: List[Tuple[TOid, TValue]],
) -> Tuple[str, List[dict]]:
    """returns formatted metrics grouped by base_oid
    """
    base = MIB_INDEX[base_oid]
    result_name = base['name']
    prefixlen = len(base_oid) + 1

    table = {}
    for oid, value in result:
        idx = oid[prefixlen:]
        prefix = oid[:prefixlen]
        if prefix not in MIB_INDEX:
            continue
        tp = MIB_INDEX[prefix]['tp']
        if tp != 'OBJECT-TYPE':
            continue
        name = MIB_INDEX[prefix]['name']
        syntax = MIB_INDEX[prefix]['syntax']
        if idx not in table:
            table[idx] = {'name': '.'.join(map(str, idx))}
        try:
            table[idx][name] = on_syntax(syntax, value)
        except Exception as e:
            raise Exception('Something went wrong in the metric processor:'
                            f' {e.__class__.__name__}: {e}')

    return result_name, list(table.values())
