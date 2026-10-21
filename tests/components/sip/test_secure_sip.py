import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.sip.sip_client.sip_transport import (
    MAX_SIP_BODY,
    MAX_SIP_HEADERS,
    SipTlsProtocol,
)
from custom_components.sip.sip_client.srtp import SdesCrypto

from .common import sip_client, sm


def _client():
    client = sip_client.SipClient(
        sip_client.SipConfig(
            server="pbx.example",
            username="alice",
            security_mode="tls_srtp",
        ),
        ssl_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
    )
    client.registered = True
    client.state = sip_client.SipState.REGISTERED
    client._local_ip = "192.0.2.1"
    client._local_port = 5090
    return client


def _sdp(
    crypto=None, *, profile="RTP/SAVP", ip="192.0.2.2", port=4000, direction="sendrecv"
):
    crypto = [SdesCrypto(1, b"r" * 30)] if crypto is None else crypto
    return (
        "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=call\r\n"
        f"c=IN IP4 {ip}\r\nt=0 0\r\nm=audio {port} {profile} 8 101\r\n"
        "a=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
        + "".join(item.sdp_attribute() for item in crypto)
        + f"a={direction}\r\n"
    )


def _request(
    method="INVITE",
    *,
    body=None,
    cseq=1,
    contact="sip:bob@192.0.2.2",
    call_id="incoming",
):
    body = _sdp() if body is None else body
    return sm.parse_sip_message(
        f"{method} sip:alice@pbx.example SIP/2.0\r\n"
        f"Via: SIP/2.0/TLS pbx.example;branch=z9hG4bK{cseq}\r\n"
        "From: <sip:bob@pbx.example>;tag=remote\r\n"
        "To: <sip:alice@pbx.example>\r\n"
        f"Contact: <{contact}>\r\n"
        f"Call-ID: {call_id}\r\nCSeq: {cseq} {method}\r\n"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {len(body.encode())}\r\n\r\n{body}"
    )


def _answer(client, body):
    return sm.parse_sip_message(
        "SIP/2.0 200 OK\r\nTo: <sip:bob@pbx.example>;tag=remote\r\n"
        "Contact: <sip:bob@192.0.2.2;transport=tls>\r\n"
        f"Call-ID: {client._d_call_id}\r\nCSeq: {client._invite_cseq} INVITE\r\n"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {len(body.encode())}\r\n\r\n{body}"
    )


def test_tls_framing_split_coalesced_octets_and_keepalive():
    packets = []
    protocol = SipTlsProtocol(packets.append, lambda: None)
    transport = MagicMock()
    protocol.connection_made(transport)
    first = b"MESSAGE sip:a@example SIP/2.0\r\nl: 2\r\n\r\n" + "é".encode()
    second = b"SIP/2.0 200 OK\r\nContent-Length :\r\n 0000000000000\r\n\r\n"
    for part in (b"\r", b"\n\r", b"\n" + first[:-1], first[-1:] + second):
        protocol.data_received(part)
    assert packets == [first, second]
    transport.write.assert_called_once_with(b"\r\n")
    transport.close.assert_not_called()


@pytest.mark.parametrize(
    "headers",
    [
        b"Content-Length: -1",
        b"Content-Length: +1",
        b"Content-Length: 1x",
        b"Content-Length: 0\r\nl: 0",
        b"Content-Length: 0\r\n 1",
        b"Via: x",
        b"Content-Length: 0\nVia: x",
        f"Content-Length: {MAX_SIP_BODY + 1}".encode(),
    ],
)
def test_tls_framing_closes_malformed_lengths(headers):
    packets = []
    protocol = SipTlsProtocol(packets.append, lambda: None)
    transport = MagicMock()
    protocol.connection_made(transport)
    protocol.data_received(b"OPTIONS sip:a@example SIP/2.0\r\n" + headers + b"\r\n\r\n")
    assert protocol.closed
    assert packets == []
    transport.close.assert_called_once()


def test_tls_framing_bounds_unterminated_headers():
    protocol = SipTlsProtocol(lambda _: None, lambda: None)
    transport = MagicMock()
    protocol.connection_made(transport)
    protocol.data_received(b"X" * (MAX_SIP_HEADERS + 1))
    assert protocol.closed
    assert not protocol._buffer
    transport.close.assert_called_once()


def test_security_mode_default_ports_and_verification_policy():
    assert sip_client.SipConfig("pbx.example").port == 5060
    assert sip_client.SipConfig("pbx.example", security_mode="tls_srtp").port == 5061
    assert (
        sip_client.SipConfig("pbx.example", 5099, security_mode="tls_srtp").port == 5099
    )

    async def run():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        with pytest.raises(ValueError):
            sip_client.SipClient(
                sip_client.SipConfig("pbx.example", security_mode="tls_srtp"),
                ssl_context=context,
            )

    asyncio.run(run())


def test_tls_certificate_failure_does_not_fall_back_to_udp():
    async def run():
        client = _client()
        with (
            patch.object(
                client._loop,
                "create_connection",
                AsyncMock(
                    side_effect=ssl.SSLCertVerificationError("certificate failed"),
                ),
            ),
            patch.object(client._loop, "create_datagram_endpoint", AsyncMock()) as udp,
        ):
            assert not await client._open_socket()
            assert client._transport is None
            udp.assert_not_awaited()
        await client.stop()

    asyncio.run(run())


def test_tls_stop_cancels_handshake_and_ignores_late_callbacks():
    async def run():
        client = _client()
        transport = MagicMock()
        started = asyncio.Event()
        protocols = []

        async def connect(factory, **kwargs):
            protocol = factory()
            protocols.append(protocol)
            protocol.connection_made(transport)
            started.set()
            await asyncio.Event().wait()

        with (
            patch.object(
                client._loop, "create_connection", AsyncMock(side_effect=connect)
            ),
            patch.object(client, "_reconnect", AsyncMock()) as reconnect,
        ):
            opening = asyncio.create_task(client.start())
            await started.wait()
            await client.stop()
            assert opening.cancelled()
            protocols[0].connection_lost(None)
            protocols[0].data_received(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
            await asyncio.sleep(0)
            assert client._transport is None
            assert client.state == sip_client.SipState.IDLE
            assert client._register_handle is None
            reconnect.assert_not_awaited()
            transport.close.assert_called()

    asyncio.run(run())


def test_tls_connection_loss_ends_call_and_reconnects_once():
    async def run():
        client = _client()
        client.state = sip_client.SipState.IN_CALL
        client._transport = MagicMock()
        client._connection_generation = 5
        ended = []
        client.cb.on_call_ended = ended.append
        started = asyncio.Event()

        async def reconnect():
            started.set()
            await asyncio.Event().wait()

        with patch.object(
            client, "_reconnect", AsyncMock(side_effect=reconnect)
        ) as retry:
            client._tls_lost(5)
            client._tls_lost(5)
            client._tls_lost(4)
            await started.wait()
            assert retry.await_count == 1
            assert ended == ["connection_lost"]
            assert not client.registered
            assert client.state == sip_client.SipState.IDLE
            await client.stop()
            client._tls_lost(client._connection_generation)
            assert retry.await_count == 1

    asyncio.run(run())


def test_secure_inbound_answer_selects_tag_without_echoing_key():
    async def run():
        client = _client()
        remote = SdesCrypto(7, b"r" * 30)
        with patch.object(client, "_send_raw") as send:
            client._handle_request(_request(body=_sdp([remote])))
            assert client.state == sip_client.SipState.INCOMING
            answer = client._build_response(client._incoming_invite, 200, "OK", True)
            assert "RTP/SAVP" in answer
            assert client._local_crypto.tag == 7
            assert client._local_crypto.key != remote.key
            assert remote.sdp_attribute() not in answer
            assert client._local_crypto.sdp_attribute() in answer
            assert ";transport=tls>" in answer
            assert len(send.call_args_list) == 2
        await client.stop()

    asyncio.run(run())


@pytest.mark.parametrize(
    "body",
    [
        _sdp(profile="RTP/AVP"),
        _sdp([]),
        _sdp().replace("AES_CM_128_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_32"),
    ],
)
def test_secure_inbound_rejects_downgrade_before_dialog_mutation(body):
    async def run():
        client = _client()
        with patch.object(client, "_send_raw") as send:
            client._handle_request(_request(body=body))
            assert send.call_args.args[0].startswith("SIP/2.0 488 ")
            assert client._d_call_id == ""
            assert client._incoming_invite is None
            assert client._remote_crypto is None
            assert client.state == sip_client.SipState.REGISTERED
        await client.stop()

    asyncio.run(run())


@pytest.mark.parametrize(
    "body",
    [
        "",
        _sdp([]),
        _sdp(profile="RTP/AVP"),
        _sdp([SdesCrypto(2, b"r" * 30)]),
        _sdp([SdesCrypto(1, b"r" * 30), SdesCrypto(2, b"s" * 30)]),
    ],
)
def test_secure_outbound_bad_answer_acks_and_byes_without_connecting(body):
    async def run():
        client = _client()
        connected, ended = [], []
        client.cb.on_call_connected = lambda: connected.append(True)
        client.cb.on_call_ended = ended.append
        with patch.object(client, "_send_raw") as send:
            client.call("bob")
            offer = send.call_args.args[0]
            assert "Via: SIP/2.0/TLS " in offer
            assert "RTP/SAVP" in offer
            assert client._local_crypto.tag == 1
            assert client._invite_retx_handle is None
            send.reset_mock()
            client._handle_invite_response(_answer(client, body))
            sent = [call.args[0] for call in send.call_args_list]
            assert sent[0].startswith("ACK ")
            assert sent[1].startswith("BYE ")
            assert connected == []
            assert ended == ["security_mismatch"]
            assert client.state == sip_client.SipState.REGISTERED
            assert not client._media_active
        await client.stop()

    asyncio.run(run())


@pytest.mark.parametrize("method", ["INVITE", "UPDATE"])
@pytest.mark.parametrize("change", ["key", "address", "profile"])
def test_secure_refresh_rejects_changes_without_mutating_dialog(method, change):
    async def run():
        client = _client()
        with patch.object(client, "_send_raw") as send:
            client._handle_request(_request())
            client.state = sip_client.SipState.IN_CALL
            client._media_active = True
            client._media_owner = client._media_session
            context = object()
            client._srtp_session = context
            before = (
                client._local_crypto,
                client._remote_crypto,
                client._remote_rtp_ip,
                client._remote_rtp_port,
                client._d_remote_target,
                client._codec,
                client._local_direction,
                client._remote_invite_cseq,
            )
            kwargs = {
                "key": {"crypto": [SdesCrypto(1, b"s" * 30)]},
                "address": {"ip": "192.0.2.3"},
                "profile": {"profile": "RTP/AVP"},
            }[change]
            request = _request(
                method, body=_sdp(**kwargs), cseq=2, contact="sip:bob@moved"
            )
            client._handle_request(request)
            assert send.call_args.args[0].startswith("SIP/2.0 488 ")
            assert client._srtp_session is context
            assert before == (
                client._local_crypto,
                client._remote_crypto,
                client._remote_rtp_ip,
                client._remote_rtp_port,
                client._d_remote_target,
                client._codec,
                client._local_direction,
                client._remote_invite_cseq,
            )
            assert client.state == sip_client.SipState.IN_CALL
        await client.stop()

    asyncio.run(run())


def test_secure_same_key_refresh_keeps_media_context_and_new_call_gets_new_key():
    async def run():
        client = _client()
        with (
            patch.object(client, "_send_raw") as send,
            patch.object(client.rtp, "start", AsyncMock(return_value=True)) as start,
        ):
            client.call("bob")
            first_key = client._local_crypto
            assert first_key.sdp_attribute() in client._build_invite()
            client._handle_invite_response(_answer(client, _sdp()))
            await asyncio.sleep(0)
            assert start.await_count == 1
            context = client._srtp_session
            for method, direction in (("INVITE", "sendonly"), ("UPDATE", "sendrecv")):
                request = _request(
                    method,
                    cseq=2,
                    body=_sdp(direction=direction),
                    call_id=client._d_call_id,
                )
                client._handle_request(request)
                assert send.call_args.args[0].startswith("SIP/2.0 200 ")
                assert client._local_direction == (
                    "recvonly" if direction == "sendonly" else "sendrecv"
                )
                await client._start_media()
                assert client._srtp_session is context
            assert start.await_count == 1
            client.rtp.on_media_error()
            assert client.last_call_reason == "media_security_error"
            assert send.call_args.args[0].startswith("BYE ")
            client.call("bob")
            assert client._local_crypto.key != first_key.key
            assert client._local_crypto.tag == 1
        await client.stop()

    asyncio.run(run())


@pytest.mark.parametrize("answer_body", ["valid", "", "wrong_tag"])
def test_secure_offerless_ack_requires_valid_answer_before_media(answer_body):
    async def run():
        client = _client()
        connected = []
        client.cb.on_call_connected = lambda: connected.append(True)
        with (
            patch.object(client, "_send_raw") as send,
            patch.object(client.rtp, "start", AsyncMock(return_value=True)) as start,
        ):
            client._handle_request(_request(body=""))
            client.answer()
            await asyncio.sleep(0)
            assert client._awaiting_answer
            start.assert_not_awaited()
            assert client._srtp_session is None
            body = {
                "valid": _sdp(),
                "": "",
                "wrong_tag": _sdp([SdesCrypto(2, b"r" * 30)]),
            }[answer_body]
            client._handle_request(_request("ACK", body=body))
            await asyncio.sleep(0)
            if answer_body == "valid":
                assert client.state == sip_client.SipState.IN_CALL
                assert connected == [True]
                assert start.await_count == 1
            else:
                assert client.state == sip_client.SipState.REGISTERED
                assert connected == []
                assert send.call_args.args[0].startswith("BYE ")
                start.assert_not_awaited()
        await client.stop()

    asyncio.run(run())
