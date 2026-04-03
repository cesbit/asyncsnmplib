from typing import NamedTuple


class UsmSecurityParameters(NamedTuple):
    authoritative_engine_id: bytes
    authoritative_engine_boots: int
    authoritative_engine_time: int
    username: bytes
    authentication_parameters: bytes
    privacy_parameters: bytes
