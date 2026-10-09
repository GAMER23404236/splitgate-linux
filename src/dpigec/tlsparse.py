"""TLS ClientHello ve HTTP isteği ayrıştırma (yalnızca konumları bulmak için)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


@dataclass
class Target:
    """Bölme konumlarının hesaplanacağı hedef bilgisi."""
    kind: str                 # "tls" | "http"
    name: str                 # SNI / Host değeri
    start: int                # ad başlangıç ofseti
    end: int                  # ad bitiş ofseti
    ext_start: int = -1       # TLS server_name uzantı başlangıcı
    method_end: int = -1      # HTTP metot sonu


def looks_like_tls(data: bytes) -> bool:
    return len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03 and data[2] <= 0x04


def tls_record_total(data: bytes) -> int:
    """İlk TLS kaydının toplam uzunluğu (başlık dahil); bilinmiyorsa -1."""
    if len(data) < 5:
        return -1
    return 5 + int.from_bytes(data[3:5], "big")


def parse_client_hello(data: bytes) -> Optional[Target]:
    """ClientHello içindeki SNI konumunu bulur; bulunamazsa None."""
    try:
        if not looks_like_tls(data) or len(data) < 44 or data[5] != 0x01:
            return None
        pos = 43
        pos += 1 + data[pos]                                   # session id
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")    # cipher suites
        pos += 1 + data[pos]                                   # compression
        ext_total = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(pos + ext_total, len(data))
        while pos + 4 <= end:
            etype = int.from_bytes(data[pos:pos + 2], "big")
            elen = int.from_bytes(data[pos + 2:pos + 4], "big")
            body = pos + 4
            if etype == 0:  # server_name
                if body + 5 > len(data):
                    return None
                ntype = data[body + 2]
                nlen = int.from_bytes(data[body + 3:body + 5], "big")
                s, e = body + 5, body + 5 + nlen
                if ntype != 0 or e > len(data) or nlen == 0:
                    return None
                name = data[s:e].decode("ascii", "ignore")
                return Target("tls", name, s, e, ext_start=pos)
            pos = body + elen
    except (IndexError, ValueError):
        return None
    return None


def looks_like_http(data: bytes) -> bool:
    return data.startswith(HTTP_METHODS)


def parse_http_request(data: bytes) -> Optional[Target]:
    """HTTP isteğinde Host değerinin konumunu bulur."""
    if not looks_like_http(data):
        return None
    method_end = data.index(b" ")
    head_end = data.find(b"\r\n\r\n")
    head = data if head_end < 0 else data[:head_end]
    low = head.lower()
    idx = low.find(b"\r\nhost:")
    if idx < 0:
        return Target("http", "", -1, -1, method_end=method_end)
    s = idx + len(b"\r\nhost:")
    while s < len(head) and head[s:s + 1] in (b" ", b"\t"):
        s += 1
    e = head.find(b"\r\n", s)
    if e < 0:
        e = len(head)
    name = head[s:e].decode("ascii", "ignore").strip()
    # port eki varsa adın bitişini ona göre daralt
    colon = head.find(b":", s, e)
    if colon > 0:
        e = colon
        name = head[s:e].decode("ascii", "ignore")
    return Target("http", name, s, e, method_end=method_end)
