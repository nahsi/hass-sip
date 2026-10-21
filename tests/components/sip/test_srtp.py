import asyncio
import base64
import struct

import pytest

from custom_components.sip.sip_client.srtp import (
    SdesCrypto,
    SrtpKeyExpired,
    SrtpSession,
    parse_crypto,
)

from .common import g711, rtp_session, sm


_KEY = base64.b64encode(bytes(range(30))).decode("ascii")


def test_sdes_parses_pbx_key_lifetime():
    crypto = parse_crypto(f"1 AES_CM_128_HMAC_SHA1_80 inline:{_KEY}|2^31")
    assert crypto == SdesCrypto(1, bytes(range(30)), 1 << 31)


@pytest.mark.parametrize(
    "attribute",
    [
        f"1 AES_CM_128_HMAC_SHA1_80 inline:{_KEY[:-4]}",
        f"1 AES_CM_128_HMAC_SHA1_80 inline:{_KEY}|2^49",
        f"1 AES_CM_128_HMAC_SHA1_80 inline:{_KEY}|1:4",
        f"1 AES_CM_128_HMAC_SHA1_80 inline:{_KEY} UNENCRYPTED_SRTP",
        f"1 AES_CM_128_HMAC_SHA1_32 inline:{_KEY}",
    ],
)
def test_sdes_rejects_unsupported_security_parameters(attribute):
    assert parse_crypto(attribute) is None


def test_sdp_keeps_audio_security_separate_from_other_media():
    attribute = f"7 AES_CM_128_HMAC_SHA1_80 inline:{_KEY}"
    sdp = sm.parse_sdp(
        "c=IN IP4 192.0.2.10\r\n"
        "a=crypto:99 ignored-session-key\r\n"
        "m=audio 4000 RTP/SAVP 0\r\n"
        f"a=crypto:{attribute}\r\n"
        "m=video 5000 RTP/AVP 8\r\n"
        "c=IN IP4 192.0.2.20\r\n"
        "a=crypto:8 ignored-video-key\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
    )
    assert sdp.media_profile == "RTP/SAVP"
    assert sdp.crypto == [attribute]
    assert sdp.connection_ip == "192.0.2.10"
    assert sdp.offered_pts == {0}
    assert sdp.pcma_pt == -1


def test_rejected_srtp_cannot_feed_audio_or_update_receive_state():
    async def run():
        local = SdesCrypto(1, bytes(range(30)))
        remote = SdesCrypto(1, bytes(range(30, 60)))
        session = rtp_session.RtpSession()
        session._srtp = SrtpSession(local, remote)
        session.set_remote("192.0.2.10", 4000)
        received = []
        session.on_audio = received.append
        sender = SrtpSession(remote, local)
        pcm = struct.pack("<160h", *([1000] * 160))
        payload = g711.encode(pcm, 0)
        packet = struct.pack(">BBHII", 0x80, 0, 1, 160, 1234) + payload
        protected = sender.protect(packet)
        try:
            session._receive_impl(protected, ("192.0.2.10", 4000))
            assert received == [g711.decode(payload, 0)]
            received_at = session._last_rx_at
            for invalid in (
                packet,
                protected,
                protected[:-1] + bytes([protected[-1] ^ 1]),
            ):
                session._receive_impl(invalid, ("192.0.2.20", 5000))
            assert received == [g711.decode(payload, 0)]
            assert session.rx_packets == 1
            assert session.bytes_received == len(pcm)
            assert session._last_rx_at == received_at
            assert session._latch_candidate is None
            assert session.sdp_remote == ("192.0.2.10", 4000)
        finally:
            await session.stop()

    asyncio.run(run())


def test_negotiated_key_lifetime_stops_protection():
    local = SdesCrypto(1, bytes(range(30)), lifetime=1)
    remote = SdesCrypto(1, bytes(range(30, 60)))
    session = SrtpSession(local, remote)
    packet = struct.pack(">BBHII", 0x80, 0, 1, 160, 1234) + bytes(160)
    session.protect(packet)
    with pytest.raises(SrtpKeyExpired):
        session.protect(struct.pack(">BBHII", 0x80, 0, 2, 320, 1234) + bytes(160))
