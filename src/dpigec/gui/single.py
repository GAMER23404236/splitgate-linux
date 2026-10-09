# Copyright (C) 2026 Project Gamers
# SPDX-License-Identifier: GPL-3.0-or-later
"""Arayüzün tek kopyası: ikinci başlatma çalışan kopyayı öne getirir, yeni pencere açmaz.

Çalışan kopya yoksa (kapatılmışsa ya da çökmüşse) yeni kopya normal açılır.

Asıl yetki bir dosya kilididir (flock): atomiktir, aynı anda başlayan iki kopyadan yalnızca biri alır ve süreç
nasıl ölürse ölsün (SIGKILL dahil) işletim sistemi bırakır; bayat kilit olmaz. Yerel soket yalnızca "göster"
isteğini taşır; kilidi tutmayan hiçbir şey "çalışan kopya" sayılmaz.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
from typing import Callable, Optional

from PyQt6.QtNetwork import QLocalServer, QLocalSocket

SHOW = b"show"   # pencereyi öne getir
PING = b"ping"   # yalnızca "canlıyım" (otomatik başlatma: pencere açılmaz)

STARTED, RUNNING, FAILED = "started", "running", "failed"


def lock_dir() -> Optional[str]:
    """Kilit dosyasının dizini: oturumun çalışma dizini; yoksa kullanıcıya özel ~/.cache/dpigec (0700).
    Paylaşımlı /tmp kullanılmaz: başka bir kullanıcı kilidi tutup başlatmayı engelleyemesin."""
    run = os.environ.get("XDG_RUNTIME_DIR")
    try:
        if run and os.path.isdir(run) and os.stat(run).st_uid == os.getuid():
            return run
    except OSError:
        pass
    d = os.path.join(os.path.expanduser("~"), ".cache", "dpigec")
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        st = os.stat(d)
    except OSError:
        return None
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        return None
    return d


def lock_path(name: str) -> Optional[str]:
    d = lock_dir()
    return os.path.join(d, name + ".lock") if d else None


def server_name() -> str:
    """Soket adı kilit dizinine bağlıdır: farklı ortamlarla başlayan kopyalar birbirinin soketini silmez."""
    tag = hashlib.sha256((lock_dir() or "").encode()).hexdigest()[:8]
    return f"dpigec-gui-{os.getuid()}-{tag}"


def notify_running(name: str, timeout_ms: int = 700, show: bool = True) -> bool:
    """Soketine bağlanılabiliyorsa mesaj gönderir ve True döner (show=False: pencere açtırmaz)."""
    sock = QLocalSocket()
    sock.connectToServer(name)
    if not sock.waitForConnected(timeout_ms):
        return False
    sock.write(SHOW if show else PING)
    sock.flush()
    sock.waitForBytesWritten(timeout_ms)
    sock.disconnectFromServer()
    return True


class Guard:
    """Bu kopya çalıştığı sürece kilidi tutar ve gelen "göster" isteklerini pencereye iletir."""

    def __init__(self, name: str, on_show: Optional[Callable[[], None]] = None) -> None:
        self.name = name
        self.on_show = on_show
        self.server: Optional[QLocalServer] = None
        self._lock_fd: Optional[int] = None

    def _take_lock(self) -> str:
        path = lock_path(self.name)
        if path is None:
            return FAILED
        try:
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        except OSError:
            return FAILED
        try:
            if os.fstat(fd).st_uid != os.getuid():
                os.close(fd)
                return FAILED
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return RUNNING
        except OSError:
            os.close(fd)
            return FAILED
        self._lock_fd = fd
        return STARTED

    def _release_lock(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    def _listen(self) -> bool:
        server = QLocalServer()
        server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)  # yalnızca bu kullanıcı bağlanabilir
        if not server.listen(self.name):
            return False
        server.newConnection.connect(self._accept)
        self.server = server
        return True

    def start(self) -> str:
        """STARTED: bu kopya tek kopya. RUNNING: başka bir kopya canlı (bu kopya kapanmalı). FAILED: koruma
        kurulamadı; kopya yine açılır (yalnızca tek-kopya koruması olmaz) ve kilit tutulmaz."""
        state = self._take_lock()
        if state != STARTED:
            return state
        # Kilidi biz tutuyoruz: canlı başka kopya yok, soket dosyası varsa bayattır.
        QLocalServer.removeServer(self.name)
        if not self._listen():
            self._release_lock()  # korumasız çalışıyoruz; sonraki başlatmalar sessizce çıkmasın
            return FAILED
        return STARTED

    def _accept(self) -> None:
        assert self.server is not None
        while self.server.hasPendingConnections():
            sock = self.server.nextPendingConnection()
            if sock is None:
                return
            sock.readyRead.connect(lambda s=sock: self._read(s))
            sock.disconnected.connect(sock.deleteLater)
            if sock.bytesAvailable():
                self._read(sock)

    def _read(self, sock: QLocalSocket) -> None:
        data = bytes(sock.read(16))
        if data.startswith(SHOW) and self.on_show is not None:
            self.on_show()

    def close(self) -> None:
        if self.server is not None:
            self.server.close()
            self.server = None
        self._release_lock()
