"""Arayüz tek kopya: çalışan kopya öne gelir, kapalıysa ya da bayat kilit varsa yenisi açılır."""
import os
import socket
import sys
import time
import unittest
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from PyQt6.QtCore import QCoreApplication
    from PyQt6.QtNetwork import QLocalServer
    from PyQt6.QtWidgets import QApplication
    HAVE_QT = True
except ImportError:  # pragma: no cover
    HAVE_QT = False


def pump(cond, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        QCoreApplication.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


@unittest.skipUnless(HAVE_QT, "PyQt6 kurulu değil")
class SingleInstanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        from dpigec.gui import single
        cls.single = single

    def setUp(self):
        self.name = "dpigec-test-" + uuid.uuid4().hex[:8]
        self.shown = []
        self.guards = []

    def tearDown(self):
        for g in self.guards:
            g.close()
        QLocalServer.removeServer(self.name)
        try:
            os.unlink(self.single.lock_path(self.name))
        except OSError:
            pass

    def guard(self):
        g = self.single.Guard(self.name, lambda: self.shown.append(1))
        self.guards.append(g)
        return g

    def test_no_running_copy_means_open_normally(self):
        self.assertFalse(self.single.notify_running(self.name, 200))
        self.assertEqual(self.guard().start(), self.single.STARTED)

    def test_second_launch_shows_the_running_one(self):
        self.assertEqual(self.guard().start(), self.single.STARTED)
        self.assertTrue(self.single.notify_running(self.name))
        self.assertTrue(pump(lambda: len(self.shown) == 1), "çalışan kopya 'göster' isteğini almadı")

    def test_every_launch_shows_again(self):
        self.guard().start()
        for _ in range(3):
            self.single.notify_running(self.name)
        self.assertTrue(pump(lambda: len(self.shown) == 3))

    def test_after_close_a_new_copy_can_start(self):
        g = self.guard()
        self.assertEqual(g.start(), self.single.STARTED)
        g.close()
        self.assertFalse(self.single.notify_running(self.name, 200))
        self.assertEqual(self.guard().start(), self.single.STARTED)

    def test_simultaneous_start_never_steals_a_live_lock(self):
        first = self.guard()
        self.assertEqual(first.start(), self.single.STARTED)
        second = self.single.Guard(self.name, lambda: self.shown.append("second"))
        self.guards.append(second)
        self.assertEqual(second.start(), self.single.RUNNING)
        self.assertIsNone(second.server)
        # İlk kopyanın kilidi hâlâ canlı ve istekleri alıyor
        self.assertTrue(self.single.notify_running(self.name))
        self.assertTrue(pump(lambda: len(self.shown) == 1))
        self.assertEqual(self.shown, [1])

    def test_lock_held_by_a_killed_process_is_released(self):
        import subprocess
        code = ("import fcntl,os,sys,time\n"
                "fd=os.open(sys.argv[1],os.O_CREAT|os.O_RDWR,0o600)\n"
                "fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
                "print('locked',flush=True)\n"
                "time.sleep(60)\n")
        p = subprocess.Popen([sys.executable, "-I", "-c", code, self.single.lock_path(self.name)],
                             stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(p.stdout.readline().strip(), "locked")
            # Başka bir (canlı) süreç kilidi tutuyor: bu kopya "çalışıyor" görür ve kapanmalıdır
            self.assertEqual(self.single.Guard(self.name).start(), self.single.RUNNING)
            p.kill()  # SIGKILL: kilit bayat kalmamalı
            p.wait()
            g = self.guard()
            self.assertEqual(g.start(), self.single.STARTED)
        finally:
            p.kill()
            p.wait()

    def test_stale_lock_file_does_not_block(self):
        # Çöken bir kopyanın bıraktığı kilit dosyası (dinleyen kimse yok)
        probe = QLocalServer()
        probe.listen(self.name)
        path = probe.fullServerName()
        probe.close()
        s = socket.socket(socket.AF_UNIX)
        s.bind(path)
        s.close()
        self.assertTrue(os.path.exists(path))
        self.assertFalse(self.single.notify_running(self.name, 200))
        self.assertEqual(self.guard().start(), self.single.STARTED, "bayat kilit yeni kopyayı engelledi")
        self.assertTrue(self.single.notify_running(self.name))
        self.assertTrue(pump(lambda: len(self.shown) == 1))

    def test_other_messages_do_not_show_the_window(self):
        from PyQt6.QtNetwork import QLocalSocket
        self.guard().start()
        c = QLocalSocket()
        c.connectToServer(self.name)
        self.assertTrue(c.waitForConnected(1000))
        c.write(b"hello")
        c.flush()
        c.waitForBytesWritten(1000)
        pump(lambda: False, 0.3)
        self.assertEqual(self.shown, [])

    def test_failed_listen_releases_the_lock(self):
        g1 = self.guard()
        g1._listen = lambda: False
        self.assertEqual(g1.start(), self.single.FAILED)
        # Korumasız çalışan kopya kilidi tutmamalı: sonraki başlatmalar sessizce çıkmasın
        self.assertEqual(self.guard().start(), self.single.STARTED)

    def test_autostart_launch_does_not_raise_the_window(self):
        self.guard().start()
        self.assertTrue(self.single.notify_running(self.name, show=False))
        pump(lambda: False, 0.3)
        self.assertEqual(self.shown, [])
        self.assertTrue(self.single.notify_running(self.name))
        self.assertTrue(pump(lambda: len(self.shown) == 1))

    def test_someone_elses_socket_cannot_block_startup(self):
        # Kilidi tutmayan biri aynı adla dinliyor (kötü niyetli ya da bayat): çalışan kopya sayılmaz
        squatter = QLocalServer()
        self.assertTrue(squatter.listen(self.name))
        try:
            self.assertEqual(self.guard().start(), self.single.STARTED)
        finally:
            squatter.close()

    def test_lock_file_symlink_is_refused(self):
        path = self.single.lock_path(self.name)
        target = path + ".target"
        open(target, "w").close()
        os.symlink(target, path)
        try:
            self.assertEqual(self.single.Guard(self.name).start(), self.single.FAILED)
        finally:
            os.unlink(path)
            os.unlink(target)

    def test_fallback_dir_is_private_not_tmp(self):
        import tempfile
        old = {k: os.environ.get(k) for k in ("XDG_RUNTIME_DIR", "HOME")}
        with tempfile.TemporaryDirectory() as home:
            try:
                os.environ.pop("XDG_RUNTIME_DIR", None)
                os.environ["HOME"] = home
                d = self.single.lock_dir()
                self.assertEqual(d, os.path.join(home, ".cache", "dpigec"))
                self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
                os.chmod(d, 0o777)  # herkese açık dizin güvenilmez
                self.assertIsNone(self.single.lock_dir())
                self.assertIsNone(self.single.lock_path("x"))
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v

    def test_socket_name_depends_on_lock_dir(self):
        import tempfile
        old = os.environ.get("XDG_RUNTIME_DIR")
        with tempfile.TemporaryDirectory() as other:
            try:
                a = self.single.server_name()
                os.environ["XDG_RUNTIME_DIR"] = other
                b = self.single.server_name()
            finally:
                if old is None:
                    os.environ.pop("XDG_RUNTIME_DIR", None)
                else:
                    os.environ["XDG_RUNTIME_DIR"] = old
        self.assertNotEqual(a, b)

    def test_socket_is_private_to_the_user(self):
        g = self.guard()
        g.start()
        mode = os.stat(g.server.fullServerName()).st_mode & 0o777
        self.assertEqual(mode & 0o077, 0, oct(mode))


if __name__ == "__main__":
    unittest.main()
