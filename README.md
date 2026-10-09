# SplitGate (Linux)

**English** · [Türkçe](README.tr.md)

A DPI bypass tool with a GUI, **written from scratch**. Made and tried on Arch Linux / CachyOS;
`install.sh` also has package lists for Debian/Ubuntu, Fedora and openSUSE, but those were not tested. It
applies system-wide, on both Wi-Fi and wired connections.

The name is SplitGate; the command, the service and the config folder keep the name `dpigec`.

## How does it work?

Most blocking happens on two layers; the tool works against both:

| Block | Solution |
|---|---|
| **DNS poisoning** (a fake IP is returned) | DNS queries are captured by a local proxy and resolved over **DoH** (Cloudflare → Google → Quad9) |
| **SNI/DPI** (the site name in the TLS handshake is read and the connection is cut) | The TLS *ClientHello* is **split into pieces** around the SNI, so DPI cannot see the site in a single packet. In plain HTTP the `Host` header is split |
| **QUIC/HTTP3** (UDP 443) | Blocked; browsers fall back to TCP automatically (so splitting can be applied) |
| **Network changes** (Wi-Fi ↔ wired ↔ phone tethering) | The service watches the default route. On a change, open connections are reset so apps reconnect over the new network, the DoH connections are renewed, and the method is checked again |
| **"Is it really working?"** | At start and after every network change the chosen method is tried on the test sites. `dpigec status` says *WORKING* only if it opens a site that a plain connection cannot; otherwise the other methods are tried, and if none works it says why (DNS, IP block, interception, DPI) |

Traffic content is never decrypted and is not routed through any other server; only the DNS lookups go to
the DoH provider. This is not a VPN; it does not hide your IP address.

```
app ──TCP 80/443──► nftables REDIRECT ──► local transparent proxy ──(split)──► internet
app ──UDP/TCP 53──► nftables REDIRECT ──► local DNS proxy ───DoH────────────► internet
```

The proxy's own outgoing connections are marked with `SO_MARK`, so there is no redirect loop.

## Installation

Grab the latest `dpigec-<version>.tar.gz` from the repository's **Releases** page (or clone the repository), unpack it and use one of the two methods below.

### Script (what the release was tested with)

```bash
./install.sh            # asks for sudo, installs dependencies + installs under /usr
./install.sh --enable --now   # also start at boot and run it right away
```

Dependencies: `python` (≥3.9), `nftables`, `polkit`, `make`, `python-pyqt6` (for the GUI).
The engine only uses the Python standard library.

### Arch / CachyOS package (not tested yet)

A `PKGBUILD` is included, but `makepkg` has not been run for this release:

```bash
make dist
cp dist/dpigec-*.tar.gz packaging/arch/
cd packaging/arch && makepkg -si
```

Uninstall: `./uninstall.sh` (`--purge` also deletes the settings).

## Usage

**GUI:** *SplitGate* from the application menu, or `dpigec-gui`.

1. **Test** tab → *Try strategies*: measures with a real TLS handshake which splitting method works on
   your network; *Apply recommended* saves it. The sites it tries are in the box above the button: put
   sites that are blocked for you there (the defaults are only examples). On the command line:
   `dpigec probe example.org example.net`.
2. Press **Start** at the top. (The administrator password is asked; polkit remembers it for a few minutes.)
3. In the *Status* tab you can tick *Start automatically at boot*.
4. With a system tray, closing the window with the X only hides it and the service keeps running; **Quit** in the tray menu stops the service and exits. (Without a tray, closing the window just exits the interface; the service keeps running.)
5. The interface opens only once: starting it again brings the running window to the front (and shows it if it
   was hidden in the tray) instead of opening a second one. If it was really closed, a new one opens.
6. The big status at the top says **Working** (green) only when the real check succeeded, i.e. the chosen method
   opens a site that a plain connection cannot. Otherwise it says *Checking…*, *Connected (not checked yet)*,
   *Connected, sites not blocked* or *Not working on this network* (red) with the reason below it.

**Command line:**

```bash
dpigec status            # state and counters
dpigec start | stop      # start/stop the service (polkit asks for a password)
dpigec enable | disable  # start automatically at boot
dpigec probe             # find the best strategy (run it with sudo, so a running service does not redirect the test)
dpigec check             # try the current method on the test sites again (the service does this by itself)
dpigec report --mail --note "what is wrong"   # problem report; opens your e-mail app
dpigec run               # without root: local SOCKS5/HTTP proxy (127.0.0.1:1080)
dpigec rules             # show the nftables rules that would be applied
dpigec lang [code]       # show or set the interface language
```

**Without root:** `dpigec run` opens a local SOCKS5/HTTP proxy. Set `127.0.0.1:1080` as the proxy in your
browser (Firefox: Settings → Network → Manual proxy). Domain names are resolved over DoH.

## Language

The default language is English. On first launch the GUI asks for your language and remembers the choice;
afterwards you can change it from the **🌐** menu in the header. On the command line: `dpigec lang` (current
language and list), `dpigec lang tr`. The environment variable `DPIGEC_LANG=tr` overrides the choice
temporarily. Service logs are always in English, regardless of the language.

To add a language, copy `src/dpigec/i18n_tr.py` and translate it (the keys are the English texts), then
add it to the `LANGUAGES` dictionary in `src/dpigec/i18n.py`; `make test` checks that the catalog is
complete.

## Settings

File: `/etc/dpigec/config.json` (the *Settings* tab of the GUI manages it). Highlights:

- **Presets:** `sni` (default), `hafif`, `agresif`, `oob`, `tlskayit` (TLS + TCP split), `disorder`, `disordersni`,
  `tlsdisorder`, `custom`. The *disorder* methods send the first piece with TTL 1 (no root needed): it dies at the
  first router before the DPI sees it, the kernel resends it, and the server gets the pieces out of order.
- **auto_method** (default `true`): if the chosen method does not open the test sites on this network, the other
  methods are tried and the one that works is used and remembered for that network.
- **Split positions** (custom): a number (bytes), `sni`, `midsld` (middle of the second-level domain),
  `sniend`, `sniext`, `host`, `hostmid`, `method` — e.g. `["1", "midsld"]`
- **Domain filter:** all sites / only the list / all except the list
- **DNS:** provider order, custom DoH provider, cache duration
- **gateway:** when enabled, traffic passing through this computer (shared) is processed as well

## Troubleshooting

- **Nothing opens, the internet is cut:** `sudo dpigec cleanup` (or `sudo nft delete table inet dpigec`)
  removes the redirect rules. When the service stops, the rules are removed automatically anyway.
- **Some sites do not open:** try another strategy from the *Test* tab; `agresif` or `oob` are needed on
  some ISPs. Very few servers do not accept a split ClientHello; for those use *All except listed* in the
  domain filter.
- **The DoH provider is blocked:** make another provider the primary one under Settings → DNS, or add a
  custom provider.
- **Firefox uses its own DoH:** No problem; splitting is still applied. If you have DNS poisoning issues,
  turn off Firefox's DoH setting and let it use the system DNS.
- **Log:** the *Log* tab in the GUI or `journalctl -u dpigec`. Visited domain names are **not** written to
  the log by default.
- **Polkit:** if `pkexec` asks for the password every time, the action may not have matched; it keeps
  working, only the password is not cached.

## Security

- The service drops all privileges except `CAP_NET_ADMIN`, and uses `ProtectSystem=strict`,
  `NoNewPrivileges`, etc.
- All privileged operations go through a single helper (`dpigecctl`); the configuration is read from
  STDIN and every field is strictly validated, only validated numbers enter the nftables text. The only
  other argument the helper accepts from the unprivileged side is the interface language code, checked
  against a fixed allowlist.
- The proxy only accepts connections for which `SO_ORIGINAL_DST` can be found (redirected ones).

## Development

```bash
make test        # unit + end-to-end tests (the transparent-mode test runs in an isolated network namespace)
```

Tests: parsers, strategy, DNS wire format, configuration validation, nftables syntax (`nft -c`),
SOCKS5/HTTP CONNECT against a fake DoH + stateless DPI simulation, transparent mode with real nftables
REDIRECT (needs root + `unshare`, skipped otherwise), headless GUI test (needs PyQt6, skipped otherwise),
and translation catalog consistency.

## Limits (an honest note)

- Splitting-based methods work against stateless/simple DPI. They may not be enough on their own against
  DPI that reassembles the stream (stateful); in that case try `oob`/`agresif`.
- Fake packet injection (a decoy ClientHello sent before the real one) is not in this version; it needs
  kernel-based packet manipulation (NFQUEUE). Out-of-order sending (*disorder*) does work without it.
- Nothing can bypass an **IP block** or an operator/modem that intercepts the connection. When that is what the
  test finds, the tool says so instead of claiming to work.
- The GUI is available in English and Turkish.

## Forks and community editions

Forks and community editions are welcome under the GPL: you may change, redistribute or sell them as long as you
share the source under the same license and keep the copyright notices. Please use a different name and your own
signing key so users do not confuse them with the official releases.

Copyright © 2026 Project Gamers. License: [GNU GPL v3 or later](LICENSE) (GPL-3.0-or-later). Anyone who modifies and distributes the
program must also share the modified source code under the same license.
