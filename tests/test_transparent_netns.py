"""Şeffaf mod uçtan uca testi: gerçek nftables REDIRECT + SO_ORIGINAL_DST.

Test, `unshare -n` ile yalnızca kendisine ait yeni bir ağ ad alanında çalışır;
ana sistemin ağına dokunmaz. root, unshare ve nftables gerekir; yoksa atlanır.
"""
import asyncio
import fcntl
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)


def _lo_up():
    s = socket.socket()
    fl = struct.unpack("16sH14x", fcntl.ioctl(s, 0x8913, struct.pack("16sH14x", b"lo", 0)))[1]
    fcntl.ioctl(s, 0x8914, struct.pack("16sH14x", b"lo", fl | 1))


async def _inner() -> None:
    from dpigec import config, firewall
    from dpigec.engine import Engine
    import test_integration as T

    _lo_up()
    env = T.Env()
    await env.setup()
    cfg = config.normalize({
        "ports": [env.dpi_port],
        "dns": {"enabled": False},
        "quic_block": False,
        "ipv6": False,
        "strategy": {"preset": "custom", "positions": ["1", "midsld"], "delay_ms": 25},
    })
    with tempfile.TemporaryDirectory() as d:
        eng = Engine(cfg, status_path=os.path.join(d, "st.json"), manage_firewall=False)
        await eng.start()
        # Test için loopback muafiyetlerini kaldır (gerçek kural kümesinin geri kalanı aynı)
        rules = firewall.render_ruleset(cfg)
        rules = rules.replace('\t\toifname "lo" return\n', "")
        rules = "\n".join(ln for ln in rules.splitlines() if "ip daddr {" not in ln) + "\n"
        res = subprocess.run(["nft", "-f", "-"], input=rules, text=True, capture_output=True)
        assert res.returncode == 0, res.stderr

        async def fetch():
            r, w = await asyncio.open_connection("127.0.0.1", env.dpi_port)
            await w.start_tls(env.client_ctx, server_hostname=T.BLOCKED)
            data = await asyncio.wait_for(r.read(32), 5)
            w.close()
            return data

        data = await fetch()
        assert data == b"merhaba-dpi", data
        assert eng.stats.tls_split == 1, eng.stats.as_dict()
        assert env.dpi_blocked == 0, env.dpi_blocked

        # Kurallar kalkınca aynı bağlantı DPI benzetimince kesilmeli
        assert firewall.remove()
        try:
            await fetch()
        except (ssl.SSLError, ConnectionError, OSError):
            pass
        else:
            raise AssertionError("kurallar kalkınca bağlantı engellenmeliydi")
        assert env.dpi_blocked == 1, env.dpi_blocked

        await eng.stop()
        assert not os.path.exists(os.path.join(d, "st.json"))
    await env.teardown()
    print("NETNS-OK")


class TransparentTests(unittest.TestCase):
    def test_transparent_redirect_in_netns(self):
        if os.geteuid() != 0 or not shutil.which("unshare") or not shutil.which("nft"):
            self.skipTest("root/unshare/nft gerekli")
        probe = subprocess.run(["unshare", "-n", "true"], capture_output=True)
        if probe.returncode != 0:
            self.skipTest("ağ ad alanı oluşturulamadı")
        res = subprocess.run(["unshare", "-n", sys.executable, os.path.abspath(__file__), "inner"],
                             capture_output=True, text=True, timeout=90)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr[-2000:])
        self.assertIn("NETNS-OK", res.stdout)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "inner":
        asyncio.run(_inner())
    else:
        unittest.main()
