"""The SP interface [SP-01 5.1]: a TUN device carrying raw IPv4 packets.

It holds the VIPs of the hosted services and only those, routes each area of
the node to itself, joins the hosted group addresses with a route to
239.0.0.0/8, and has the SP MTU.

    Linux    /dev/net/tun (IFF_TUN | IFF_NO_PI), configured with ``ip``;
             needs CAP_NET_ADMIN. VIPs are never answered by ARP on physical
             interfaces: arp_ignore=1 / arp_announce=2 are set. The SP
             interface accepts packets whose source is one of our own
             addresses (accept_local=1, rp_filter=0, on it only): every
             instance of a service holds the same VIP, so what another
             instance sends from it, to the group address, arrives with our
             VIP as its source, which Linux otherwise drops as a martian.
    Windows  Wintun (wintun.dll next to the program or on PATH), configured
             with ``netsh``; needs administrator rights.
    other    an in-memory interface: packets written are kept, nothing is
             delivered to the system. Used when neither of the above can be
             opened, so the node still runs (and says so), and in tests.
"""

from __future__ import annotations

import asyncio
import ctypes
import logging
import os
import socket
import struct
import subprocess
import sys
import threading
from collections import deque
from typing import Callable

log = logging.getLogger("usmd_rdsh.sp")

NAME = "usmd-sp"


class MemoryTun:
    """No system interface: written packets are kept for inspection."""

    kind = "memory"
    #: Why no system interface could be opened ("" for an interface asked for).
    reason = ""

    def __init__(self, mtu: int, on_packet: Callable[[bytes], None]) -> None:
        self.mtu = mtu
        self.on_packet = on_packet
        self.written: deque[bytes] = deque(maxlen=256)
        self.vips: list[str] = []
        self.routes: list[str] = []
        self.groups: list[str] = []

    def configure(self, vips: list[str], routes: list[str], groups: list[str]) -> None:
        self.vips, self.routes, self.groups = list(vips), list(routes), list(groups)

    def write(self, packet: bytes) -> None:
        self.written.append(packet)

    def inject(self, packet: bytes) -> None:
        """A packet 'read' from the interface (tests, diagnostics)."""
        self.on_packet(packet)

    async def start(self) -> None:
        log.warning("[SP] No TUN device available: SP interface simulated in memory")

    async def stop(self) -> None:
        return None


class Memberships:
    """Group addresses joined on the SP interface [SP 5.1], one socket holding them."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.joined: dict[str, bytes] = {}

    def update(self, groups, request) -> None:
        for group in set(self.joined) - set(groups):
            try:
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP,
                                     self.joined.pop(group))
            except OSError:
                pass
        for group in set(groups) - set(self.joined):
            mreq = request(group)
            try:
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                self.joined[group] = mreq
            except OSError as exc:
                log.error("[SP] Could not join %s on the SP interface: %s", group, exc)


def _run(*command: str) -> None:
    subprocess.run(command, check=False, capture_output=True)


def _set_interface_knob(knob: str, value: str, *, root: str = "/proc/sys/net/ipv4/conf") -> bool:
    """One IPv4 setting of the SP interface; a failure is said, not ignored:
    without accept_local the instances of a service never hear each other."""
    path = os.path.join(root, NAME, knob)
    try:
        with open(path, "w", encoding="ascii") as setting:
            setting.write(value)
        return True
    except OSError as exc:
        log.error("[SP] Could not set %s=%s on %s (%s): the instances of a service will "
                  "not receive what the others send to its group address", knob, value, NAME,
                  exc.strerror or exc)
        return False


class LinuxTun(MemoryTun):
    """/dev/net/tun."""

    kind = "linux"
    TUNSETIFF = 0x400454CA
    IFF_TUN, IFF_NO_PI = 0x0001, 0x1000

    def __init__(self, mtu: int, on_packet: Callable[[bytes], None]) -> None:
        super().__init__(mtu, on_packet)
        import fcntl  # pylint: disable=import-outside-toplevel

        self.fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        request = struct.pack("16sH", NAME.encode(), self.IFF_TUN | self.IFF_NO_PI)
        fcntl.ioctl(self.fd, self.TUNSETIFF, request)
        _run("ip", "link", "set", NAME, "mtu", str(mtu), "up")
        for knob, value in (("arp_ignore", "1"), ("arp_announce", "2")):
            _run("sysctl", "-w", f"net.ipv4.conf.all.{knob}={value}")
        for knob, value in (("accept_local", "1"), ("rp_filter", "0")):
            _set_interface_knob(knob, value)
        self._applied: tuple[list[str], list[str], list[str]] = ([], [], [])
        self._memberships = Memberships()
        self._ifindex = socket.if_nametoindex(NAME)

    def _ifindex_request(self, group: str) -> bytes:
        """ip_mreqn: group, any local address, the SP interface index."""
        return socket.inet_aton(group) + socket.inet_aton("0.0.0.0") + \
            struct.pack("@i", self._ifindex)

    def configure(self, vips: list[str], routes: list[str], groups: list[str]) -> None:
        old_vips, old_routes, old_groups = self._applied
        for vip in set(old_vips) - set(vips):
            _run("ip", "addr", "del", f"{vip}/32", "dev", NAME)
        for vip in set(vips) - set(old_vips):
            _run("ip", "addr", "add", f"{vip}/32", "dev", NAME)
        for route in set(old_routes) - set(routes):
            _run("ip", "route", "del", route, "dev", NAME)
        for route in set(routes) - set(old_routes):
            _run("ip", "route", "replace", route, "dev", NAME)
        self._memberships.update(groups, self._ifindex_request)
        self._applied = (list(vips), list(routes), list(groups))
        super().configure(vips, routes, groups)

    def write(self, packet: bytes) -> None:
        try:
            os.write(self.fd, packet)
        except OSError:
            pass

    def _readable(self) -> None:
        try:
            while True:
                self.on_packet(os.read(self.fd, 65535))
        except BlockingIOError:
            return
        except OSError:
            return

    async def start(self) -> None:
        asyncio.get_running_loop().add_reader(self.fd, self._readable)

    async def stop(self) -> None:
        try:
            asyncio.get_running_loop().remove_reader(self.fd)
        finally:
            os.close(self.fd)


class WintunTun(MemoryTun):
    """Wintun on Windows (wintun.dll must be loadable)."""

    kind = "wintun"

    def __init__(self, mtu: int, on_packet: Callable[[bytes], None]) -> None:
        super().__init__(mtu, on_packet)
        self.dll = ctypes.WinDLL("wintun.dll")  # type: ignore[attr-defined]
        dll = self.dll
        dll.WintunCreateAdapter.restype = ctypes.c_void_p
        dll.WintunStartSession.restype = ctypes.c_void_p
        dll.WintunReceivePacket.restype = ctypes.c_void_p
        dll.WintunAllocateSendPacket.restype = ctypes.c_void_p
        dll.WintunGetReadWaitEvent.restype = ctypes.c_void_p
        self.adapter = dll.WintunCreateAdapter(NAME, "USMD", None)
        if not self.adapter:
            raise OSError("WintunCreateAdapter failed (administrator rights?)")
        self.session = dll.WintunStartSession(ctypes.c_void_p(self.adapter), 0x400000)
        if not self.session:
            raise OSError("WintunStartSession failed")
        _run("netsh", "interface", "ipv4", "set", "subinterface", NAME, f"mtu={mtu}",
             "store=active")
        self._stop = threading.Event()
        self._memberships = Memberships()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._applied: tuple[list[str], list[str]] = ([], [])

    def configure(self, vips: list[str], routes: list[str], groups: list[str]) -> None:
        old_vips, old_routes = self._applied
        for vip in set(old_vips) - set(vips):
            _run("netsh", "interface", "ipv4", "delete", "address", NAME, vip)
        for vip in set(vips) - set(old_vips):
            _run("netsh", "interface", "ipv4", "add", "address", NAME, vip, "255.255.255.255")
        for route in set(old_routes) - set(routes):
            _run("netsh", "interface", "ipv4", "delete", "route", route, NAME)
        for route in set(routes) - set(old_routes):
            _run("netsh", "interface", "ipv4", "add", "route", route, NAME, "store=active")
        # Joined on the SP interface, addressed by one of its VIPs.
        if vips:
            local = socket.inet_aton(vips[0])
            self._memberships.update(groups, lambda g: socket.inet_aton(g) + local)
        self._applied = (list(vips), list(routes))
        super().configure(vips, routes, groups)

    def write(self, packet: bytes) -> None:
        buffer = self.dll.WintunAllocateSendPacket(ctypes.c_void_p(self.session), len(packet))
        if buffer:
            ctypes.memmove(buffer, packet, len(packet))
            self.dll.WintunSendPacket(ctypes.c_void_p(self.session), ctypes.c_void_p(buffer))

    def _reader(self) -> None:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        event = self.dll.WintunGetReadWaitEvent(ctypes.c_void_p(self.session))
        size = ctypes.c_uint32()
        while not self._stop.is_set():
            packet = self.dll.WintunReceivePacket(ctypes.c_void_p(self.session),
                                                  ctypes.byref(size))
            if not packet:
                kernel32.WaitForSingleObject(ctypes.c_void_p(event), 250)
                continue
            data = ctypes.string_at(packet, size.value)
            self.dll.WintunReleaseReceivePacket(ctypes.c_void_p(self.session),
                                                ctypes.c_void_p(packet))
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self.on_packet, data)

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        threading.Thread(target=self._reader, name="wintun-reader", daemon=True).start()

    async def stop(self) -> None:
        self._stop.set()
        self.dll.WintunEndSession(ctypes.c_void_p(self.session))
        self.dll.WintunCloseAdapter(ctypes.c_void_p(self.adapter))


def open_tun(*, mtu: int, on_packet: Callable[[bytes], None],
             backend: str = "auto") -> MemoryTun:
    """The best interface this host allows."""
    reason = ""
    if backend in ("auto", "linux") and sys.platform.startswith("linux"):
        try:
            return LinuxTun(mtu, on_packet)
        except OSError as exc:
            reason = f"/dev/net/tun: {exc.strerror or exc}"
            if exc.errno in (1, 13):  # EPERM, EACCES
                reason += " (the node needs CAP_NET_ADMIN: run it as the usmd service)"
            log.warning("[SP] %s", reason)
    if backend in ("auto", "wintun") and sys.platform == "win32":
        try:
            return WintunTun(mtu, on_packet)
        except (OSError, AttributeError) as exc:
            reason = f"Wintun: {exc} (wintun.dll and administrator rights)"
            log.warning("[SP] %s", reason)
    tun = MemoryTun(mtu, on_packet)
    tun.reason = reason or ("" if backend == "memory" else "no TUN backend on this system")
    return tun
