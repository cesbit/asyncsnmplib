[![CI](https://github.com/cesbit/asyncsnmplib/workflows/CI/badge.svg)](https://github.com/cesbit/asyncsnmplib/actions)
[![Release Version](https://img.shields.io/github/release/cesbit/asyncsnmplib)](https://github.com/cesbit/asyncsnmplib/releases)

# Python Async SNMP Library

## Installation

```
pip install asyncsnmplib
```

## Example

```python
from asyncsnmplib.client import Snmp


async def main():
    oid = (1, 3, 6, 1, 2, 1, 1, 1, 0)

    host = '127.0.0.1'
    community = 'public'

    cl = Snmp(host, community=community)
    await cl.connect()

    # GET
    res = await cl.get(oid)
    oid, tag, value = res
    print(f'OID: {oid}\nTAG: {tag}\nVALUE: {value}')

    # GETNEXT
    res = await cl.get_next(oid)
    oid, tag, value = res
    print(f'OID: {oid}\nTAG: {tag}\nVALUE: {value}')

    # GETBULK
    varbinds = await cl.get_bulk(oid, max_repetitions=20)
    for oid, tag, value in varbinds:
        print(f'OID: {oid} | TAG: {tag} | VALUE: {value}')

    # walk an OID tree
    varbinds = await cl.walk(oid)
    for oid, tag, value in varbinds:
        print(f'OID: {oid} | TAG: {tag} | VALUE: {value}')

    cl.close()


if __name__ == '__main__':
    logger = logging.getLogger('asyncsnmplib')
    logger.setLevel(logging.DEBUG)

    asyncio.run(main())
```

## Example SNMPv3

```python
from asyncsnmplib.client import SnmpV3
from asyncsnmplib.v3.auth import USM_AUTH_HMAC96_SHA
from asyncsnmplib.v3.encr import USM_PRIV_CFB128_AES


async def main():
    oid = (1, 3, 6, 1, 2, 1, 1, 1, 0)

    host = '127.0.0.1'
    username = 'User'
    auth = (USM_AUTH_HMAC96_SHA, 'Password1')
    priv = (USM_PRIV_CFB128_AES, 'Password2')

    cl = SnmpV3(host, username=username, auth=auth, priv=priv)
    await cl.connect()

    # GET
    res = await cl.get(oid)
    oid, tag, value = res
    print(f'OID: {oid}\nTAG: {tag}\nVALUE: {value}')

    cl.close()


if __name__ == '__main__':
    logger = logging.getLogger('asyncsnmplib')
    logger.setLevel(logging.DEBUG)

    asyncio.run(main())
```