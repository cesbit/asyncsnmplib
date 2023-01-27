import logging
from .client import Snmp, SnmpV1, SnmpV3
from .exceptions import SnmpNoConnection, SnmpNoAuthParams
from .mib.utils import on_result_base
from .v3.auth import AUTH_PROTO
from .v3.encr import PRIV_PROTO


class InvalidConfigException(Exception):
    pass


class MissingCredentialsException(InvalidConfigException):
    pass


class InvalidCredentialsException(InvalidConfigException):
    pass


class InvalidClientConfigException(InvalidConfigException):
    pass


class ParseResultException(Exception):
    pass


def snmpv3_credentials(config: dict):
    try:
        user_name = config['username']
    except KeyError:
        raise Exception(f'missing `username`')

    auth = config.get('auth')
    if auth is not None:
        auth_type = auth.get('type', 'USM_AUTH_NONE')
        if auth_type != 'USM_AUTH_NONE':
            if auth_type not in AUTH_PROTO:
                raise Exception(f'invalid `auth.type`')

            try:
                auth_passwd = auth['password']
            except KeyError:
                raise Exception(f'missing `auth.password`')

            priv = config.get('priv', {})
            priv_type = priv.get('type', 'USM_PRIV_NONE')
            if priv_type != 'USM_PRIV_NONE':
                if priv_type not in PRIV_PROTO:
                    raise Exception(f'invalid `priv.type`')

                try:
                    priv_passwd = priv['password']
                except KeyError:
                    raise Exception(f'missing `priv.password`')

                return {
                    'username': user_name,
                    'auth_proto': auth_type,
                    'auth_passwd': auth_passwd,
                    'priv_proto': priv_type,
                    'priv_passwd': priv_passwd,
                }
            else:
                return {
                    'username': user_name,
                    'auth_proto': auth_type,
                    'auth_passwd': auth_passwd,
                }
        else:
            return {
                'username': user_name,
            }


async def snmp_queries(
        address: str,
        config: dict,
        queries: tuple):

    version = config.get('version', '2c')
    community = config.get('community', 'public')
    if not isinstance(community, str):
        try:
            community = community['secret']
            assert isinstance(community, str)
        except KeyError:
            logging.warning(f'missing snmp credentials {address}')
            raise MissingCredentialsException

    if version == '2c':
        cl = Snmp(
            host=address,
            community=community,
        )
    elif version == '3':
        try:
            cred = snmpv3_credentials(config)
        except Exception as e:
            logging.warning(f'invalid snmpv3 credentials {address}: {e}')
            raise InvalidCredentialsException
        try:
            cl = SnmpV3(
                host=address,
                **cred,
            )
        except Exception as e:
            logging.warning(f'invalid snmpv3 client config {address}: {e}')
            raise InvalidClientConfigException
    elif version == '1':
        cl = SnmpV1(
            host=address,
            community=community,
        )
    else:
        logging.warning(f'unsupported snmp version {address}: {version}')
        raise InvalidClientConfigException

    try:
        await cl.connect()
    except SnmpNoConnection as e:
        raise
    except SnmpNoAuthParams:
        logging.warning(f'unable to connect: failed to set auth params')
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
                    f'parse result error: {msg}')
            else:
                results[name] = parsed_result
        return results
    finally:
        # safe to close whatever the connection status is
        cl.close()
