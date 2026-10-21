from __future__ import annotations

import base64
import binascii
import os
import re
from dataclasses import dataclass, field

import pylibsrtp

CRYPTO_SUITE = "AES_CM_128_HMAC_SHA1_80"
MAX_KEY_PACKETS = 1 << 48


@dataclass(frozen=True)
class SdesCrypto:
    tag: int
    key: bytes = field(repr=False)
    lifetime: int | None = None

    @classmethod
    def generate(cls, tag: int = 1) -> SdesCrypto:
        return cls(tag=tag, key=os.urandom(30))

    def sdp_attribute(self) -> str:
        key = base64.b64encode(self.key).decode("ascii")
        lifetime = f"|{self.lifetime}" if self.lifetime is not None else ""
        return f"a=crypto:{self.tag} {CRYPTO_SUITE} inline:{key}{lifetime}\r\n"


def parse_crypto(value: str) -> SdesCrypto | None:
    fields = value.split()
    if (
        len(fields) != 3
        or re.fullmatch(r"[1-9][0-9]{0,8}", fields[0]) is None
        or fields[1].upper() != CRYPTO_SUITE
    ):
        return None
    match = re.fullmatch(
        r"(?i:inline):([A-Za-z0-9+/]{40})(?:\|(2\^[0-9]{1,2}|[0-9]{1,15}))?",
        fields[2],
    )
    if match is None:
        return None
    try:
        key = base64.b64decode(match[1], validate=True)
    except binascii.Error:
        return None
    if len(key) != 30:
        return None
    lifetime = None
    if value := match[2]:
        if value.startswith("2^"):
            exponent = int(value[2:])
            if exponent > 48:
                return None
            lifetime = 1 << exponent
        else:
            lifetime = int(value)
        if not 1 <= lifetime <= MAX_KEY_PACKETS:
            return None
    return SdesCrypto(tag=int(fields[0]), key=key, lifetime=lifetime)


class SrtpKeyExpired(Exception):
    pass


class SrtpSession:
    def __init__(self, local: SdesCrypto, remote: SdesCrypto) -> None:
        self._tx = pylibsrtp.Session(
            pylibsrtp.Policy(
                key=local.key,
                ssrc_type=pylibsrtp.Policy.SSRC_ANY_OUTBOUND,
                srtp_profile=pylibsrtp.Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
            )
        )
        self._rx = pylibsrtp.Session(
            pylibsrtp.Policy(
                key=remote.key,
                ssrc_type=pylibsrtp.Policy.SSRC_ANY_INBOUND,
                srtp_profile=pylibsrtp.Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
            )
        )
        self._tx_limit = local.lifetime or MAX_KEY_PACKETS
        self._rx_limit = remote.lifetime or MAX_KEY_PACKETS
        self._sent = 0
        self._received = 0

    def protect(self, packet: bytes) -> bytes:
        if self._sent >= self._tx_limit:
            raise SrtpKeyExpired
        protected = self._tx.protect(packet)
        self._sent += 1
        return protected

    def unprotect(self, packet: bytes) -> bytes:
        if self._received >= self._rx_limit:
            raise SrtpKeyExpired
        unprotected = self._rx.unprotect(packet)
        self._received += 1
        return unprotected
