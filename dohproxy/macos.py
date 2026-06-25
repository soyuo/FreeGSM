"""macOS DNS interception via pf.

macOS has no WinDivert equivalent. This module installs a temporary pf anchor
that redirects TCP/UDP port 53 to local DoH proxies and clears it on shutdown.
"""

from __future__ import annotations

import logging
import ctypes
import fcntl
import os
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
from pathlib import Path

from . import config, doh, dpi
from .dnsutil import describe_query

log = logging.getLogger("dohproxy.macos")

_ANCHOR = "com.apple/freegsm"
def _default_interface() -> str:
    proc = subprocess.run(
        ["route", "-n", "get", "default"],
        check=False,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"route -n get default failed: {proc.stderr.strip()}")
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError("could not find default route interface")


def _pf_rules() -> str:
    upstream_hi = config.UPSTREAM_PORT_BASE + config.UPSTREAM_PORT_COUNT - 1
    iface = _default_interface()
    return f"""\
no rdr inet proto tcp from any port {config.UPSTREAM_PORT_BASE}:{upstream_hi} to any port 443
no rdr on lo0 inet proto tcp from any port {config.UPSTREAM_PORT_BASE}:{upstream_hi} to any port 443
no rdr inet proto tcp from any to any port {{{config.TCP_PROXY_PORT}, {config.HTTPS_PROXY_PORT}}}
no rdr on lo0 inet proto tcp from any to any port {{{config.TCP_PROXY_PORT}, {config.HTTPS_PROXY_PORT}}}
rdr pass inet proto udp from any to any port 53 -> 127.0.0.1 port {config.TCP_PROXY_PORT}
rdr pass inet proto tcp from any to any port 53 -> 127.0.0.1 port {config.TCP_PROXY_PORT}
rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port {config.HTTPS_PROXY_PORT}
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port {config.HTTPS_PROXY_PORT}
block drop quick inet proto udp from any to any port 443
pass out on {iface} inet route-to (lo0 127.0.0.1) proto tcp from any to any port 443
"""


def _run_pfctl(*args: str) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["pfctl", *args],
        check=False,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"pfctl {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc


class _PfAnchor:
    def __init__(self) -> None:
        self._token: str | None = None

    def install(self) -> None:
        rules = Path(tempfile.gettempdir()) / "freegsm-pf.conf"
        rules.write_text(_pf_rules(), encoding="utf-8")
        _run_pfctl("-a", _ANCHOR, "-f", str(rules))
        enabled = _run_pfctl("-E")
        parts = f"{enabled.stdout}\n{enabled.stderr}".split()
        self._token = parts[-1] if parts else None
        log.info(
            "pf anchor %s loaded; DNS TCP/UDP :53 redirects to 127.0.0.1:%d",
            _ANCHOR,
            config.TCP_PROXY_PORT,
        )
        if config.DPI_BYPASS:
            log.info(
                "TCP/443 redirects to 127.0.0.1:%d; UDP/443 is dropped to force TCP fallback",
                config.HTTPS_PROXY_PORT,
            )

    def clear(self) -> None:
        try:
            _run_pfctl("-a", _ANCHOR, "-F", "all")
        except Exception as exc:  # noqa: BLE001
            log.debug("pf anchor clear failed: %s", exc)
        if self._token:
            try:
                _run_pfctl("-X", self._token)
            except Exception as exc:  # noqa: BLE001
                log.debug("pf disable-token release failed: %s", exc)
            self._token = None
        log.info("pf anchor %s cleared", _ANCHOR)


def _recv_exactly(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)
    return bytes(buf)


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock = self.request
        while True:
            header = _recv_exactly(sock, 2)
            if len(header) < 2:
                return
            (length,) = struct.unpack("!H", header)
            query = _recv_exactly(sock, length)
            if len(query) < length:
                return

            desc = describe_query(query)
            log.info("[INTERCEPT] TCP  %s  (from %s)", desc, self.client_address[0])
            try:
                answer = doh.resolve(query)
            except Exception as exc:  # noqa: BLE001
                log.warning("[FAILED]    TCP  %s  -> DoH error: %s; closing", desc, exc)
                return

            log.info("[RESOLVED]  TCP  %s  -> %d bytes", desc, len(answer))
            sock.sendall(struct.pack("!H", len(answer)) + answer)


class _TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _PfAddr(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_ubyte * 16)]


class _PfiocNatlook(ctypes.Structure):
    _fields_ = [
        ("saddr", _PfAddr),
        ("daddr", _PfAddr),
        ("rsaddr", _PfAddr),
        ("rdaddr", _PfAddr),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("rsport", ctypes.c_uint16),
        ("rdport", ctypes.c_uint16),
        ("af", ctypes.c_uint8),
        ("proto", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("log", ctypes.c_uint8),
    ]


_DIOCNATLOOK = 0xC0000000 | (ctypes.sizeof(_PfiocNatlook) << 16) | (ord("D") << 8) | 23
_PF_OUT = 1


class _NatHandle:
    def __init__(self) -> None:
        self._fd = os.open("/dev/pf", os.O_RDONLY)

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def original_dest(self, client_addr, local_addr) -> tuple[str, int]:
        src_ip, src_port = client_addr[:2]
        dst_ip, dst_port = local_addr[:2]
        nl = _PfiocNatlook()
        ctypes.memmove(nl.saddr.addr, socket.inet_aton(src_ip), 4)
        ctypes.memmove(nl.daddr.addr, socket.inet_aton(dst_ip), 4)
        nl.sport = socket.htons(src_port)
        nl.dport = socket.htons(dst_port)
        nl.af = socket.AF_INET
        nl.proto = socket.IPPROTO_TCP
        nl.direction = _PF_OUT

        try:
            fcntl.ioctl(self._fd, _DIOCNATLOOK, nl, True)
        except OSError:
            nl.direction = 0
            fcntl.ioctl(self._fd, _DIOCNATLOOK, nl, True)

        ip = socket.inet_ntoa(bytes(nl.rdaddr.addr[:4]))
        return ip, socket.ntohs(nl.rdport)


_port_lock = threading.Lock()
_next_port = config.UPSTREAM_PORT_BASE


def _connect_upstream(server_ip: str, server_port: int) -> socket.socket:
    global _next_port
    base = config.UPSTREAM_PORT_BASE
    hi = base + config.UPSTREAM_PORT_COUNT
    last_err: Exception | None = None

    for _ in range(config.UPSTREAM_PORT_COUNT):
        with _port_lock:
            port = _next_port
            _next_port = port + 1 if port + 1 < hi else base

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            last_err = exc
            sock.close()
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(config.HTTPS_CONNECT_TIMEOUT)
            sock.connect((server_ip, server_port))
            sock.settimeout(None)
            return sock
        except OSError:
            sock.close()
            raise

    raise OSError(f"no free upstream port in reserved range ({last_err})")


def _pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65535)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _HttpsHandler(socketserver.BaseRequestHandler):
    nat: _NatHandle

    def handle(self) -> None:
        client = self.request
        try:
            server_ip, server_port = self.nat.original_dest(self.client_address, client.getsockname())
        except OSError as exc:
            log.warning("[HTTPS] original destination lookup failed: %s", exc)
            return

        try:
            upstream = _connect_upstream(server_ip, server_port)
        except OSError as exc:
            log.warning("[HTTPS] upstream %s:%d failed: %s", server_ip, server_port, exc)
            return

        try:
            self._relay(client, upstream, server_ip, server_port)
        finally:
            upstream.close()

    def _relay(self, client, upstream, server_ip, server_port) -> None:
        client.settimeout(config.HTTPS_FIRST_READ_TIMEOUT)
        try:
            first = client.recv(65535)
        except (socket.timeout, OSError):
            return
        client.settimeout(None)
        if not first:
            return

        try:
            if first[0] == dpi._TLS_HANDSHAKE:
                segs = dpi.split_hello(first, config.SPLIT_MIN, config.SPLIT_MAX)
                log.info(
                    "[HTTPS] %s:%d  SNI=%s  ClientHello %dB -> %d TLS records",
                    server_ip, server_port, dpi.sni_name(first), len(first), len(segs),
                )
                for seg in segs:
                    upstream.sendall(seg)
            else:
                upstream.sendall(first)
        except OSError:
            return

        reverse = threading.Thread(
            target=_pump, args=(upstream, client), name="macos-https-pump", daemon=True
        )
        reverse.start()
        _pump(client, upstream)
        reverse.join(timeout=2.0)


class _HttpsServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Runtime:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._pf = _PfAnchor()
        self._nat: _NatHandle | None = None
        self._udp_sock: socket.socket | None = None
        self._tcp_server: _TcpServer | None = None
        self._https_server: _HttpsServer | None = None
        self._threads: list[threading.Thread] = []

    def start(self) -> "Runtime":
        self._start_udp_proxy()
        self._start_tcp_proxy()
        self._nat = _NatHandle()
        if config.DPI_BYPASS:
            self._start_https_relay()
        self._pf.install()
        return self

    def _start_udp_proxy(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", config.TCP_PROXY_PORT))
        sock.settimeout(0.2)
        self._udp_sock = sock
        thread = threading.Thread(target=self._udp_loop, name="macos-udp-dns", daemon=True)
        thread.start()
        self._threads.append(thread)
        log.info("UDP DoH proxy listening on 127.0.0.1:%d", config.TCP_PROXY_PORT)

    def _udp_loop(self) -> None:
        assert self._udp_sock is not None
        while not self._stop.is_set():
            try:
                query, peer = self._udp_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not query:
                continue

            desc = describe_query(query)
            log.info("[INTERCEPT] UDP  %s  (from %s)", desc, peer[0])
            try:
                answer = doh.resolve(query)
            except Exception as exc:  # noqa: BLE001
                log.warning("[FAILED]    UDP  %s  -> DoH error: %s; dropped", desc, exc)
                continue
            log.info("[RESOLVED]  UDP  %s  -> %d bytes", desc, len(answer))
            self._udp_sock.sendto(answer, peer)

    def _start_tcp_proxy(self) -> None:
        self._tcp_server = _TcpServer(("127.0.0.1", config.TCP_PROXY_PORT), _TcpHandler)
        thread = threading.Thread(target=self._tcp_server.serve_forever, name="macos-tcp-dns", daemon=True)
        thread.start()
        self._threads.append(thread)
        log.info("TCP DoH proxy listening on 127.0.0.1:%d", config.TCP_PROXY_PORT)

    def _start_https_relay(self) -> None:
        assert self._nat is not None
        handler = type("_BoundHttpsHandler", (_HttpsHandler,), {"nat": self._nat})
        self._https_server = _HttpsServer(("127.0.0.1", config.HTTPS_PROXY_PORT), handler)
        thread = threading.Thread(
            target=self._https_server.serve_forever,
            name="macos-https-relay",
            daemon=True,
        )
        thread.start()
        self._threads.append(thread)
        log.info(
            "HTTPS splitting relay listening on 127.0.0.1:%d (upstream ports %d-%d)",
            config.HTTPS_PROXY_PORT,
            config.UPSTREAM_PORT_BASE,
            config.UPSTREAM_PORT_BASE + config.UPSTREAM_PORT_COUNT - 1,
        )

    def is_alive(self) -> bool:
        return not self._stop.is_set()

    def stop(self) -> None:
        self._stop.set()
        self._pf.clear()
        if self._udp_sock is not None:
            self._udp_sock.close()
        if self._tcp_server is not None:
            self._tcp_server.shutdown()
            self._tcp_server.server_close()
        if self._https_server is not None:
            self._https_server.shutdown()
            self._https_server.server_close()
        if self._nat is not None:
            self._nat.close()


def start() -> Runtime:
    return Runtime().start()
