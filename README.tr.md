# SplitGate (Linux)

[English](README.md) · **Türkçe**

**Sıfırdan yazılmış**, arayüzlü bir DPI atlatma aracı. Arch Linux / CachyOS'ta yapıldı ve denendi;
`install.sh` Debian/Ubuntu, Fedora ve openSUSE için de paket listesi içerir ama bunlarda denenmedi.
Wi-Fi ve kablolu bağlantıların ikisinde de geçerlidir (sistem geneli).

Adı SplitGate; komut, servis ve ayar klasörü `dpigec` adını koruyor.

## Nasıl çalışır?

Engellerin çoğu iki katmandır; araç ikisine de karşı çalışır:

| Engel | Çözüm |
|---|---|
| **DNS zehirlemesi** (sahte IP döner) | DNS sorguları yerel bir vekilde yakalanır ve **DoH** (Cloudflare → Google → Quad9) ile çözülür |
| **SNI/DPI** (TLS el sıkışmasındaki site adı okunup bağlantı kesilir) | TLS *ClientHello* SNI üzerinden **parçalara bölünerek** gönderilir; DPI siteyi tek pakette göremez. Düz HTTP'de `Host` başlığı bölünür |
| **QUIC/HTTP3** (UDP 443) | Engellenir; tarayıcı otomatik TCP'ye döner (böylece bölme uygulanabilir) |
| **Ağ değişimi** (Wi-Fi ↔ kablolu ↔ telefon paylaşımı) | Servis varsayılan rotayı izler. Değişince açık bağlantılar sıfırlanır (uygulamalar yeni ağdan hemen yeniden bağlanır), DoH bağlantıları yenilenir ve yöntem yeniden kontrol edilir |
| **"Gerçekten çalışıyor mu?"** | Başlangıçta ve her ağ değişiminde seçili yöntem test sitelerinde denenir. `dpigec status`, ancak yöntem bölmesiz bağlantının açamadığı bir siteyi açıyorsa *ÇALIŞIYOR* der; açmıyorsa diğer yöntemler denenir, hiçbiri olmazsa nedenini (DNS, IP engeli, araya girme, DPI) yazar |

Trafiğin içeriği çözülmez ve başka bir sunucudan geçmez; yalnızca DNS sorguları DoH sağlayıcısına gider.
Bu bir VPN değildir; IP adresinizi gizlemez.

```
uygulama ──TCP 80/443──► nftables REDIRECT ──► yerel şeffaf vekil ──(bölünmüş)──► internet
uygulama ──UDP/TCP 53──► nftables REDIRECT ──► yerel DNS vekili ───DoH────────► internet
```

Vekilin kendi giden bağlantıları `SO_MARK` ile işaretlenir; böylece yönlendirme döngüsü oluşmaz.

## Kurulum

Deponun **Releases** sayfasından en son `dpigec-<sürüm>.tar.gz` dosyasını indirin (ya da depoyu klonlayın), açın ve aşağıdaki iki yoldan birini kullanın.

### Betik (sürümün denendiği yol)

```bash
./install.sh            # sudo ister, bağımlılıkları kurar + /usr altına kurar
./install.sh --enable --now   # ayrıca açılışta başlat ve hemen çalıştır
```

Bağımlılıklar: `python` (≥3.9), `nftables`, `polkit`, `make`, `python-pyqt6` (arayüz için).
Motor yalnızca Python standart kütüphanesini kullanır.

### Arch / CachyOS paketi (henüz denenmedi)

Bir `PKGBUILD` var ama bu sürüm için `makepkg` çalıştırılmadı:

```bash
make dist
cp dist/dpigec-*.tar.gz packaging/arch/
cd packaging/arch && makepkg -si
```

Kaldırma: `./uninstall.sh` (`--purge` ayarları da siler).

## Kullanım

**Arayüz:** uygulama menüsünden *SplitGate* ya da `dpigec-gui`.

1. **Test** sekmesi → *Stratejileri dene*: ağınızda hangi bölme yönteminin çalıştığını gerçek TLS
   el sıkışmasıyla ölçer; *Önerileni uygula* ile kaydeder. Denenen siteler butonun üstündeki kutuda: senin için
   engelli olan siteleri oraya yazın (varsayılanlar yalnızca örnektir). Komut satırında:
   `dpigec probe ornek.org ornek.net`.
2. Üstteki **Başlat** düğmesine basın. (Yönetici şifresi istenir; polkit onu birkaç dakika hatırlar.)
3. *Durum* sekmesinden *açılışta otomatik başlat*ı işaretleyebilirsiniz.
4. Sistem tepsisi varsa pencereyi X ile kapatmak onu yalnızca gizler, servis çalışmaya devam eder; tepsi menüsündeki **Çık** servisi durdurur ve çıkar. (Tepsi yoksa pencereyi kapatmak yalnızca arayüzden çıkar, servis çalışmaya devam eder.)
5. Arayüz yalnızca bir kez açılır: yeniden başlatmak ikinci bir pencere açmaz, çalışanı öne getirir (tepside
   gizliyse gösterir). Gerçekten kapatıldıysa yenisi açılır.
6. Üstteki büyük durum, **Çalışıyor** (yeşil) yazısını yalnızca gerçek kontrol başarılıysa gösterir; yani seçili yöntem
   bölmesiz bağlantının açamadığı bir siteyi açıyorsa. Aksi halde *Kontrol ediliyor…*, *Bağlı (henüz kontrol
   edilmedi)*, *Bağlı, siteler engelli değil* ya da kırmızı *Bu ağda çalışmıyor* yazar ve nedeni altında gösterir.

**Komut satırı:**

```bash
dpigec status            # durum ve sayaçlar
dpigec start | stop      # servisi başlat/durdur (polkit şifre sorar)
dpigec enable | disable  # açılışta otomatik başlat
dpigec probe             # en iyi stratejiyi bul (sudo ile çalıştırın; çalışan servis testi yönlendirmesin)
dpigec check             # seçili yöntemi test sitelerinde yeniden dene (servis bunu kendisi de yapar)
dpigec report --mail --note "sorun ne"   # sorun raporu; e-posta uygulamasını açar
dpigec run               # root olmadan: yerel SOCKS5/HTTP vekil (127.0.0.1:1080)
dpigec rules             # uygulanacak nftables kurallarını göster
dpigec lang [kod]        # arayüz dilini göster veya ayarla
```

**Root'suz kullanım:** `dpigec run` yerel bir SOCKS5/HTTP vekil açar. Tarayıcıda vekil olarak
`127.0.0.1:1080` verin (Firefox: Ayarlar → Ağ → Elle vekil). Alan adları DoH ile çözülür.

## Dil

Varsayılan dil İngilizcedir. Arayüz ilk açıldığında dili sorar; seçiminiz kaydedilir. Sonradan başlık
çubuğundaki **🌐** menüsünden değiştirebilirsiniz. Komut satırında: `dpigec lang` (mevcut dil ve liste),
`dpigec lang tr`. Ortam değişkeni `DPIGEC_LANG=tr` seçimi geçici olarak ezer. Servis günlükleri dilden
bağımsız olarak İngilizcedir.

Yeni dil eklemek için `src/dpigec/i18n_tr.py` dosyasını kopyalayıp çevirin (anahtarlar İngilizce metinlerdir),
`src/dpigec/i18n.py` içindeki `LANGUAGES` sözlüğüne ekleyin; `make test` katalogun eksiksizliğini denetler.

## Ayarlar

Dosya: `/etc/dpigec/config.json` (arayüz *Ayarlar* sekmesi bunu yönetir). Öne çıkanlar:

- **Ön ayarlar:** `sni` (varsayılan), `hafif`, `agresif`, `oob`, `tlskayit` (TLS + TCP böl), `disorder`, `disordersni`,
  `tlsdisorder`, `custom`. *disorder* yöntemleri ilk parçayı TTL 1 ile gönderir (root gerekmez): ilk router'da DPI'a
  varmadan ölür, çekirdek onu yeniden gönderir ve sunucuya parçalar sırasız ulaşır.
- **auto_method** (varsayılan `true`): seçili yöntem bu ağda test sitelerini açmıyorsa diğerleri denenir; çalışan
  kullanılır ve o ağ için hatırlanır.
- **Bölme konumları** (custom): sayı (bayt), `sni`, `midsld` (alan adının ortası), `sniend`,
  `sniext`, `host`, `hostmid`, `method` — örn. `["1", "midsld"]`
- **Alan adı filtresi:** tüm siteler / yalnızca liste / liste hariç
- **DNS:** sağlayıcı sırası, özel DoH sağlayıcısı, önbellek süresi
- **gateway:** açılırsa bu bilgisayardan geçen (paylaşılan) trafik de işlenir

## Sorun giderme

- **Hiçbir şey açılmıyor, internet kesildi:** `sudo dpigec cleanup` (ya da `sudo nft delete table inet dpigec`)
  yönlendirme kurallarını kaldırır. Servis durunca kurallar zaten otomatik silinir.
- **Bazı siteler açılmıyor:** *Test* sekmesinden başka bir strateji deneyin; `agresif` veya `oob` bazı
  ISS'lerde gerekir. Çok az sayıda sunucu bölünmüş ClientHello'yu kabul etmez; bunlar için
  alan adı filtresinde *Listedekiler hariç* kullanın.
- **DoH sağlayıcısı engelli:** Ayarlar → DNS bölümünden başka sağlayıcıyı birincil yapın veya özel
  sağlayıcı ekleyin.
- **Firefox kendi DoH'unu kullanıyor:** Sorun değil; bölme yine uygulanır. DNS zehirlenmesi
  sorunu yaşıyorsanız Firefox'un DoH ayarını kapatıp sistem DNS'ine bırakın.
- **Günlük:** arayüzde *Günlük* sekmesi veya `journalctl -u dpigec`.
  Ziyaret edilen alan adları varsayılan olarak günlüğe **yazılmaz**.
- **Polkit:** `pkexec` her seferinde şifre soruyorsa eylem eşleşmemiş olabilir; çalışmaya devam eder,
  yalnızca şifre önbelleğe alınmaz.

## Güvenlik

- Servis `CAP_NET_ADMIN` dışındaki tüm yetkileri bırakır, `ProtectSystem=strict`, `NoNewPrivileges` vb.
- Yetkili işlemlerin tamamı tek bir yardımcıdan (`dpigecctl`) geçer; yapılandırma STDIN'den
  alınır ve her alan sıkı doğrulanır, nftables metnine yalnızca doğrulanmış sayılar girer. Yardımcının ayrıcalıksız taraftan kabul ettiği tek ek argüman arayüz dil kodudur; sabit bir izin listesine karşı denetlenir.
- Vekil, yalnızca `SO_ORIGINAL_DST` bulunabilen (yönlendirilmiş) bağlantıları kabul eder.

## Geliştirme

```bash
make test        # birim + uçtan uca testler (şeffaf mod testi izole ağ ad alanında çalışır)
```

Testler: ayrıştırıcılar, strateji, DNS tel biçimi, yapılandırma doğrulama, nftables söz dizimi
(`nft -c`), sahte DoH + durumsuz DPI benzetimine karşı SOCKS5/HTTP CONNECT, gerçek nftables
REDIRECT ile şeffaf mod (root + `unshare` gerekir, yoksa atlanır), başsız GUI testi
(PyQt6 gerekir, yoksa atlanır) ve çeviri kataloğunun tutarlılığı.

## Sınırlar (dürüst not)

- Bölme tabanlı yöntemler, durumsuz/basit DPI'lara karşı etkilidir. Akışı yeniden birleştiren
  (stateful) DPI'lara karşı tek başına yetmeyebilir; bu durumda `oob`/`agresif` denenebilir.
- Sahte paket enjeksiyonu (gerçeğinden önce sahte bir ClientHello) bu sürümde yoktur; çekirdek tabanlı paket
  manipülasyonu (NFQUEUE) gerektirir. Sıra bozma (*disorder*) bunsuz çalışır.
- **IP engelini** ya da bağlantıya araya giren bir operatör/modemi hiçbir yöntem aşamaz. Test bunu bulursa araç
  çalışıyormuş gibi yapmaz, bunu söyler.
- Arayüz İngilizce ve Türkçedir (yukarıdaki Dil bölümüne bakın); yeni bir dil eklemek tek bir çeviri dosyası ister.

## Çatallar ve topluluk sürümleri

Çatallar ve topluluk sürümleri GPL kapsamında serbesttir: kaynağı aynı lisansla paylaşıp telif bildirimlerini
korudukları sürece değiştirebilir, dağıtabilir ve satabilirler. Kullanıcılar resmî sürümlerle karıştırmasın diye
lütfen farklı bir ad ve kendi imza anahtarınızı kullanın.

Telif hakkı © 2026 Project Gamers. Lisans: [GNU GPL v3 veya üstü](LICENSE) (GPL-3.0-or-later). Programı değiştirip dağıtan herkes, değişen kaynak kodunu da aynı lisansla paylaşmak zorundadır.
