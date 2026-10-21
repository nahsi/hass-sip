from __future__ import annotations

import asyncio
import re
from typing import Callable

MAX_SIP_HEADERS = 65536
MAX_SIP_BODY = 1048576
CONNECT_TIMEOUT = 15.0
HANDSHAKE_TIMEOUT = 10.0
_HEADER_NAME = re.compile(rb"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
_START_LINE = re.compile(
    rb"(?:SIP/2\.0 [1-6][0-9]{2} [^\r\n]*|"
    rb"[A-Za-z0-9!#$%&'*+.^_`|~-]+ [^ \r\n]+ SIP/2\.0)"
)


class SipTlsProtocol(asyncio.Protocol):
    def __init__(
        self,
        on_packet: Callable[[bytes], None],
        on_lost: Callable[[], None],
    ) -> None:
        self._on_packet = on_packet
        self._on_lost = on_lost
        self.transport: asyncio.Transport | None = None
        self.closed = False
        self._buffer = bytearray()
        self._message_size: int | None = None
        self._keepalive_lines = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        if self.closed:
            transport.close()
            return
        self.transport = transport

    def pause_writing(self) -> None:
        if self.transport is not None:
            self.transport.pause_reading()

    def resume_writing(self) -> None:
        if self.transport is not None and not self.closed:
            self.transport.resume_reading()

    def close(self) -> None:
        self.closed = True
        self._buffer.clear()
        if self.transport is not None:
            self.transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        self.close()
        self._on_lost()

    def data_received(self, data: bytes) -> None:
        for offset in range(0, len(data), MAX_SIP_HEADERS):
            if self.closed:
                return
            self._buffer.extend(data[offset : offset + MAX_SIP_HEADERS])
            if not self._drain():
                self.close()
                return

    def _drain(self) -> bool:
        while self._buffer:
            if self._message_size is None:
                if self._buffer.startswith(b"\r\n"):
                    del self._buffer[:2]
                    self._keepalive_lines += 1
                    if self._keepalive_lines == 2:
                        if self.transport is not None:
                            self.transport.write(b"\r\n")
                        self._keepalive_lines = 0
                    continue
                end = self._buffer.find(b"\r\n\r\n")
                if end < 0:
                    return len(self._buffer) <= MAX_SIP_HEADERS
                if end + 4 > MAX_SIP_HEADERS:
                    return False
                lines = self._buffer[:end].split(b"\r\n")
                if not _START_LINE.fullmatch(lines[0]):
                    return False
                length = None
                index = 1
                while index < len(lines):
                    name, sep, value = lines[index].partition(b":")
                    name = name.rstrip(b" \t")
                    if not sep or not _HEADER_NAME.fullmatch(name):
                        return False
                    index += 1
                    values = [value]
                    while index < len(lines) and lines[index].startswith((b" ", b"\t")):
                        values.append(lines[index].lstrip(b" \t"))
                        index += 1
                    value = b" ".join(values)
                    if b"\r" in value or b"\n" in value:
                        return False
                    if name.lower() in (b"content-length", b"l"):
                        value = value.strip(b" \t")
                        if length is not None or not value.isdigit():
                            return False
                        value = value.lstrip(b"0") or b"0"
                        if len(value) > len(str(MAX_SIP_BODY)):
                            return False
                        length = int(value)
                if length is None or length > MAX_SIP_BODY:
                    return False
                self._message_size = end + 4 + length
                self._keepalive_lines = 0
            if len(self._buffer) < self._message_size:
                return True
            packet = bytes(self._buffer[: self._message_size])
            del self._buffer[: self._message_size]
            self._message_size = None
            self._on_packet(packet)
            if self.closed:
                return True
        return True
