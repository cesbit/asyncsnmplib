import asyncio
import logging
import time
from typing import Type, Callable, Awaitable, Optional
from .auth import Auth
from .encr import Priv
from .usm import UsmSecurityParameters


class SnmpV3Cache:
    _lock: asyncio.Lock
    _params: Optional[tuple[UsmSecurityParameters, float]]

    def __init__(
        self,
        username: str,
        auth: Optional[tuple[Type[Auth], str]] = None,
        priv: Optional[tuple[Type[Priv], str]] = None,
    ):
        self._lock = asyncio.Lock()
        self._params = None

        self._username = username.encode()
        self._auth_proto = None
        self._auth_hash = None
        self._auth_hash_localized = None
        self._priv_proto = None
        self._priv_hash = None
        self._priv_hash_localized = None
        if auth is not None:
            self._auth_proto, auth_passwd = auth
            self._auth_hash = self._auth_proto.hash_passphrase(auth_passwd)
            if priv is not None:
                self._priv_proto, priv_passwd = priv
                self._priv_hash = self._auth_proto.hash_passphrase(priv_passwd)

    async def get_params(self,
                         load: Callable[[], Awaitable[UsmSecurityParameters]]
                         ) -> tuple[UsmSecurityParameters, bool]:
        async with self._lock:
            if self._params is None:
                logging.info('Retrieve new authentication params')
                params = await load()
                self.set_params(params)
                return params, True
            usm_params, last_boot_time = self._params
            return UsmSecurityParameters(
                usm_params.authoritative_engine_id,
                usm_params.authoritative_engine_boots,
                int(time.time() - last_boot_time),
                usm_params.username,
                usm_params.authentication_parameters,
                usm_params.privacy_parameters,
            ), False

    def set_params(self, usm_params: UsmSecurityParameters):
        if self._auth_proto:
            self._auth_hash_localized = self._auth_proto.localize(
                self._auth_hash, usm_params.authoritative_engine_id)
            if self._priv_proto:
                self._priv_hash_localized = self._auth_proto.localize(
                    self._priv_hash, usm_params.authoritative_engine_id)

        last_boot_time = time.time() - usm_params.authoritative_engine_time
        self._params = (usm_params, last_boot_time)

    def clear(self):
        self._params = None
