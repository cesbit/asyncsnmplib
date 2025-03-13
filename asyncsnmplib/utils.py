import logging
from typing import Dict, List, Tuple
from .asn1 import TOid, TValue
from .client import Snmp, SnmpV1, SnmpV3
from .exceptions import SnmpException, SnmpNoConnection, SnmpNoAuthParams
from .mib.utils import on_result_base
from .v3.auth import AUTH_PROTO
from .v3.encr import PRIV_PROTO


class InvalidConfigException(SnmpException):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class ParseResultException(SnmpException):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


async def snmp_queries(
        address: str,
        config: dict,
        queries: Tuple[TOid, ...]) -> Dict[str, List[Dict[str, TValue]]]:

    version = config.get('version', '2c')

    if version == '2c':
        community = config.get('community', 'public')
        if isinstance(community, dict):
            community = community.get('secret')
        if not isinstance(community, str):
            raise InvalidConfigException('`community` must be a string.')
        cl = Snmp(
            host=address,
            community=community,
        )
    elif version == '3':
        username = config.get('username')
        if not isinstance(username, str):
            raise InvalidConfigException('`username` must be a string.')
        auth = config.get('auth')
        if auth:
            auth_proto = AUTH_PROTO.get(auth.get('type'))
            auth_passwd = auth.get('password')
            if auth_proto is None:
                raise InvalidConfigException('`auth.type` invalid')
            elif not isinstance(auth_passwd, str):
                raise InvalidConfigException('`auth.password` must be string')
            auth = (auth_proto, auth_passwd)
        priv = auth and config.get('priv')
        if priv:
            priv_proto = PRIV_PROTO.get(priv.get('type'))
            priv_passwd = priv.get('password')
            if priv_proto is None:
                raise InvalidConfigException('`priv.type` invalid')
            elif not isinstance(priv_passwd, str):
                raise InvalidConfigException('`priv.password` must be string')
            priv = (priv_proto, priv_passwd)
        cl = SnmpV3(
            host=address,
            username=username,
            auth=auth,
            priv=priv,
        )
    elif version == '1':
        community = config.get('community', 'public')
        if isinstance(community, dict):
            community = community.get('secret')
        if not isinstance(community, str):
            raise InvalidConfigException('`community` must be a string.')
        cl = SnmpV1(
            host=address,
            community=community,
        )
    else:
        raise InvalidConfigException(f'unsupported snmp version {version}')

    try:
        await cl.connect()
    except SnmpNoConnection:
        raise
    except SnmpNoAuthParams:
        logging.warning('unable to connect: failed to set auth params')
        raise
    else:
        results = {}
        for oid in queries:
            result = await cl.walk(oid)
            try:
                name, parsed_result = on_result_base(oid, result)
            except Exception as e:
                msg = str(e) or type(e).__name__
                raise ParseResultException(
                    f'Failed to parse result. Exception: {msg}')
            else:
                results[name] = parsed_result
        return results
    finally:
        # safe to close whatever the connection status is
        cl.close()
