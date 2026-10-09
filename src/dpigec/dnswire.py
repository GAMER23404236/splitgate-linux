"""Minimal DNS tel biçimi (wire format) yardımcıları - yalnızca standart kütüphane."""
from __future__ import annotations

import ipaddress
import random
import struct
from typing import List, Tuple


class DNSError(ValueError):
    pass


QTYPE_A = 1
QTYPE_AAAA = 28


def build_query(name: str, qtype: int, qid: int = None) -> bytes:
    if qid is None:
        qid = random.getrandbits(16)
    out = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii") if label.isascii() else label.encode("idna")
        if not 0 < len(raw) < 64:
            raise DNSError("invalid label")
        out += bytes([len(raw)]) + raw
    return out + b"\x00" + struct.pack("!HH", qtype, 1)


def parse_header(data: bytes) -> Tuple[int, int, int, int, int, int]:
    if len(data) < 12:
        raise DNSError("short message")
    return struct.unpack_from("!HHHHHH", data, 0)


def _skip_name(data: bytes, off: int) -> int:
    while True:
        if off >= len(data):
            raise DNSError("truncated name")
        ln = data[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise DNSError("truncated pointer")
            return off + 2
        if ln & 0xC0:
            raise DNSError("invalid label type")
        off += 1 + ln


def is_query(data: bytes) -> bool:
    return len(data) >= 12 and not (data[2] & 0x80)


def question_key(data: bytes) -> bytes:
    """Önbellek anahtarı: soru bölümü (küçük harfe çevrilmiş, ID'siz)."""
    _id, _flags, qd, _an, _ns, _ar = parse_header(data)
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    if off > len(data):
        raise DNSError("truncated question")
    return data[12:off].lower()


def set_id(data: bytes, qid: int) -> bytes:
    return struct.pack("!H", qid) + data[2:]


def servfail(query: bytes) -> bytes:
    """Sorguya karşılık SERVFAIL yanıtı üretir."""
    qid, flags, qd, _an, _ns, _ar = parse_header(query)
    off = 12
    for _ in range(qd):
        off = _skip_name(query, off) + 4
    rflags = 0x8000 | (flags & 0x0100) | 0x0080 | 2
    return struct.pack("!HHHHHH", qid, rflags, qd, 0, 0, 0) + query[12:off]


def truncate(resp: bytes) -> bytes:
    """Yanıtı yalnızca soru bölümüyle, TC (kesildi) bitiyle yeniden üretir."""
    qid, flags, qd, _an, _ns, _ar = parse_header(resp)
    off = 12
    for _ in range(qd):
        off = _skip_name(resp, off) + 4
    return struct.pack("!HHHHHH", qid, flags | 0x0200, qd, 0, 0, 0) + resp[12:off]


def parse_answers(data: bytes) -> Tuple[int, List[str], int]:
    """(rcode, [ip adresleri], en küçük TTL) döndürür."""
    _id, flags, qd, an, _ns, _ar = parse_header(data)
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    addrs: List[str] = []
    ttls: List[int] = []
    for _ in range(an):
        off = _skip_name(data, off)
        if off + 10 > len(data):
            raise DNSError("truncated record")
        rtype, _rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, off)
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if off > len(data):
            raise DNSError("truncated rdata")
        ttls.append(ttl)
        if rtype == QTYPE_A and rdlen == 4:
            addrs.append(str(ipaddress.IPv4Address(rdata)))
        elif rtype == QTYPE_AAAA and rdlen == 16:
            addrs.append(str(ipaddress.IPv6Address(rdata)))
    return flags & 0xF, addrs, (min(ttls) if ttls else 0)
