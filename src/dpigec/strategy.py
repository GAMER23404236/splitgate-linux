"""Bölme stratejisi: konum belirteçlerini ofsetlere çevirir, veriyi parçalar."""
from __future__ import annotations

from typing import List, Optional, Tuple

from .tlsparse import Target, tls_record_total

# ".com.tr" gibi iki parçalı son ekler için ikinci seviye alan adı tespiti
_SLD_PREFIXES = {"com", "net", "org", "edu", "gov", "co", "gen", "web", "info", "biz", "k12", "av", "bel"}


def _sld_mid(target: Target) -> Optional[int]:
    """İkinci seviye alan adının (ör. 'discord') orta noktasının ofseti."""
    if target.start < 0 or not target.name:
        return None
    labels = target.name.split(".")
    idx = len(labels) - 2
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD_PREFIXES:
        idx = len(labels) - 3
    if idx < 0:
        idx = 0
    label_start = target.start + sum(len(x) + 1 for x in labels[:idx])
    return label_start + max(1, len(labels[idx]) // 2)


def resolve_positions(specs: List[str], length: int, target: Optional[Target]) -> List[int]:
    """Konum belirteçlerini (0, length) aralığında sıralı, tekil ofsetlere çevirir."""
    out = set()
    for spec in specs:
        pos: Optional[int] = None
        if spec.isdigit():
            pos = int(spec)
        elif target is not None:
            if spec in ("sni", "host") and target.start >= 0:
                pos = target.start
            elif spec == "hostmid" and target.start >= 0:
                pos = target.start + max(1, (target.end - target.start) // 2)
            elif spec == "sniend" and target.end >= 0:
                pos = target.end
            elif spec == "sniext" and target.ext_start >= 0:
                pos = target.ext_start
            elif spec == "midsld":
                pos = _sld_mid(target)
            elif spec == "method" and target.method_end >= 0:
                pos = target.method_end
        if pos is not None and 0 < pos < length:
            out.add(pos)
    return sorted(out)


def split_payload(data: bytes, positions: List[int]) -> List[bytes]:
    segs: List[bytes] = []
    prev = 0
    for p in positions:
        if p > prev:
            segs.append(data[prev:p])
            prev = p
    segs.append(data[prev:])
    return [s for s in segs if s]


def tls_record_split(data: bytes, cut: int) -> Optional[bytes]:
    """İlk TLS kaydını `cut` ofsetinden iki ayrı kayda böler; yeni kaydın sınırı yine `cut` olur.

    Kayıt eksikse ya da kesim kaydın dışındaysa None.
    """
    total = tls_record_total(data)
    if total < 0 or len(data) < total or not 5 < cut < total:
        return None
    head = data[:3]
    first = data[5:cut]
    second = data[cut:total]
    return (head + len(first).to_bytes(2, "big") + first
            + head + len(second).to_bytes(2, "big") + second + data[total:])


def plan_segments(data: bytes, target: Optional[Target], kind: str, positions: List[str],
                  tlsrec: bool) -> Tuple[List[bytes], str]:
    """İlk veriyi gönderilecek parçalara ayırır. Dönen metin günlük için kısa açıklamadır.

    tlsrec: TLS'te ilk konum belirtecinden iki TLS kaydı yapılır ve kayıt sınırı TCP sınırı olur;
    kayıt bölünemezse (ya da HTTP'de) aynı noktadan yalnızca TCP bölmesi yapılır.
    """
    if tlsrec:
        cut = resolve_positions(positions[:1] or ["hostmid"], len(data), target)
        if not cut:
            return [data], "no split point"
        if kind == "tls":
            rec = tls_record_split(data, cut[0])
            if rec is not None:
                return [rec[:cut[0]], rec[cut[0]:]], f"TLS record + TCP split @{cut[0]}"
        return split_payload(data, cut), f"split @{cut[0]} (record not split)"
    pos = resolve_positions(positions, len(data), target)
    return split_payload(data, pos), "split @" + ",".join(map(str, pos))


def mix_host_case(data: bytes, target: Target) -> bytes:
    """'Host:' başlığını 'hOsT:' yapar (aynı uzunluk; ofsetler değişmez)."""
    if target.kind != "http" or target.start < 0:
        return data
    low = data.lower()
    idx = low.find(b"\r\nhost:")
    if idx < 0:
        return data
    s = idx + 2
    return data[:s] + b"hOsT" + data[s + 4:]


def domain_matches(host: str, domains: List[str]) -> bool:
    host = host.lower().rstrip(".")
    for d in domains:
        if host == d or host.endswith("." + d):
            return True
    return False


def should_desync(mode: str, domains: List[str], name: str) -> bool:
    """Alan adı filtresine göre bölme uygulanacak mı?"""
    if mode == "all":
        return True
    if not name:
        return mode == "exclude"
    hit = domain_matches(name, domains)
    return hit if mode == "include" else not hit
