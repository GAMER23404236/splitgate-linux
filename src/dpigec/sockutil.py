"""Soket yardımcıları: işaretli (SO_MARK) soket, orijinal hedef, ayarlar."""
from __future__ import annotations

import logging
import socket
import struct
from typing import Optional, Tuple

log = logging.getLogger("dpigec")

SO_MARK = getattr(socket, "SO_MARK", 36)
SO_ORIGINAL_DST = 80  # <linux/netfilter_ipv4.h>
_warned_mark = False


def make_marked_socket(family: int, mark: int) -> socket.socket:
    """Motorun kendi giden bağlantıları için işaretli, bloklamayan TCP soketi.

    İşaret, nftables kurallarında yönlendirme döngüsünü engeller. SO_MARK
    CAP_NET_ADMIN gerektirir; yetki yoksa (kullanıcı modunda SOCKS) işaretsiz
    devam edilir - bu modda yönlendirme kuralı da yoktur.
    """
    global _warned_mark
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
    except PermissionError:
        if not _warned_mark:
            log.debug("could not set SO_MARK (no privilege); continuing unmarked")
            _warned_mark = True
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    s.setblocking(False)
    return s


def set_ttl(sock: socket.socket, ttl: int) -> bool:
    """Giden paketlerin TTL'ini (IPv6'da hop limitini) ayarlar; -1 sistem varsayılanına döndürür.

    Root gerektirmez. IPv6 soketin IPv4-mapped hedefinde IP_TTL geçerlidir.
    """
    try:
        if sock.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            except OSError:
                pass
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        return True
    except OSError:
        return False


def original_dst(sock) -> Optional[Tuple[str, int]]:
    """REDIRECT edilmiş bağlantının özgün hedefi (ip, port); alınamazsa None."""
    try:
        if sock.family == socket.AF_INET:
            raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port = struct.unpack_from("!H", raw, 2)[0]
            return socket.inet_ntoa(raw[4:8]), port
        raw = sock.getsockopt(socket.IPPROTO_IPV6, SO_ORIGINAL_DST, 28)
        port = struct.unpack_from("!H", raw, 2)[0]
        return socket.inet_ntop(socket.AF_INET6, raw[8:24]), port
    except (OSError, struct.error):
        return None


def listen_socket(family: int, host: str, port: int, backlog: int = 512) -> socket.socket:
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((host, port))
    s.listen(backlog)
    s.setblocking(False)
    return s


def is_ip(host: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except OSError:
            continue
    return False
