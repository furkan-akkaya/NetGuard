# Öğrenme notu 09 — Sertleştirme: localhost'a saldırmak, tedarik zinciri ve sandbox

> Faz 9 · İlgili kod: `web/guard.py`, `deploy/netguard.service`, `.github/workflows/`
> İlgili doküman: [THREAT_MODEL.md](../THREAT_MODEL.md), [DEPLOYMENT.md](../DEPLOYMENT.md)

## 1. "Yalnızca localhost'ta çalışıyor, güvenli" yanılgısı

`127.0.0.1`'e bağlanan bir servise ağdan kimse ulaşamaz. Ama **tarayıcın**
ulaşır. Açtığın her web sayfası JavaScript çalıştırır ve o JavaScript senin
makinendeki localhost'a istek gönderebilir. Bu fazın başında NetGuard'a iki
somut saldırı denedim. İkisi de işe yaradı:

**DNS rebinding.** Saldırgan `kotu.example` alan adını önce kendi sunucusuna,
birkaç saniye sonra `127.0.0.1`'e çözdürür. Tarayıcı için sayfa hâlâ
`kotu.example` kaynağıdır (aynı origin), ama istekler artık NetGuard'a gider.
Token yoksa sayfa tüm yakalamaları ve alarmları okuyabilir. Ayırt edici iz:
istek `Host: kotu.example` başlığını taşır. Savunma, **Host allowlist**:
yalnızca loopback adları ve `--allowed-host` ile verilen adlar kabul ediliyor,
gerisi 421.

**CSRF ve "basit istekler".** Tarayıcı bazı çapraz-site istekleri CORS
preflight olmadan gönderir: yöntem POST, içerik türü `text/plain`,
`application/x-www-form-urlencoded` ya da `multipart/form-data` ise. NetGuard
yükleme ve profil içe aktarmada gövdeyi içerik türüne bakmadan okuyordu.
Kötü bir sayfa kullanıcı fark etmeden bir yakalama yükleyebiliyor ve bir
kuralı kapatan profil oluşturabiliyordu. Savunma iki katmanlı:

1. Durum değiştiren isteklerde `Origin` başlığı sunucunun kendisi değilse 403.
2. Ham gövdeli uç noktalar yalnızca `application/octet-stream` ya da
   `application/toml` kabul ediyor. Bu türler cross-site istekte preflight
   gerektirir, NetGuard da preflight'a hiç cevap vermez.

Ders: localhost güvenlik sınırı değildir; tarayıcı, saldırganın içeride
çalıştırdığı bir istemcidir.

## 2. Tedarik zinciri: bağımlılıkları kim denetliyor?

NetGuard'ın çalışma zamanında 16 Python paketi ve 3 doğrudan JavaScript bağımlılığı (dolaylılarla birlikte daha fazlası) var.
Her biri saldırı yüzeyi:

- **Kilit dosyaları** (`uv.lock`, `pnpm-lock.yaml`) tam sürümleri ve hash'leri
  sabitler. CI `--locked` / `--frozen-lockfile` ile kurar, yani sessizce yeni
  bir sürüm gelemez.
- **pip-audit / pnpm audit**: bilinen açıkları arar. CI'da her PR'da ve **her
  hafta** çalışıyor, çünkü kod değişmese de yeni açıklar yayınlanır.
- **Lisans kapısı**: GPL/AGPL/LGPL/SSPL bir bağımlılık, MIT lisanslı NetGuard'ı
  dağıtmayı etkiler. Burada küçük ama öğretici bir hata yakaladım: ilk
  yazdığım regex `"GPL` arıyordu, ama PyPI lisansı
  `GNU General Public License v3 (GPLv3)` diye yazar. Kapıyı bilerek kötü bir
  örnekle test edince açık ortaya çıktı. **Bir güvenlik kontrolünü, yakalaması
  gereken şeyle test etmeden güvenme.**
- **SBOM** (CycloneDX): her release ile hangi bileşenlerin hangi sürümlerle
  gönderildiğinin makine-okunur listesi. Yeni bir açık duyurulduğunda
  "etkileniyor muyuz?" sorusu dakikalar içinde cevaplanır.

## 3. Sandbox: systemd ile en az yetki

`deploy/netguard.service`, NetGuard'ı neredeyse hiçbir şeye erişemeyen bir
kullanıcıyla çalıştırır: boş capability seti, salt okunur sistem, ev dizinlerine
erişim yok, özel `/tmp` ve bir **sistem çağrısı allowlist'i**
(`@system-service`). `systemd-analyze security` maruziyeti 1,6 ("OK") olarak
ölçüyor.

Gerçek bir tuzak: ilk sürümde `SystemCallFilter=~@resources` vardı. Güzel
görünüyor, kaynak sistem çağrılarını yasaklıyor. Ama her analiz worker'ı
kendi bellek sınırını koymak için `setrlimit()` çağırıyor. systemd bu durumda
worker'ı `SIGSYS` ile öldürürdü ve her analiz "çöktü" olarak biterdi. Grupları
açıp hangi çağrının nerede olduğunu kontrol ederek düzelttim. glibc modern
çekirdeklerde `setrlimit` yerine `prlimit64` kullanır; o da `@default`
grubunda. Sandbox kuralı yazarken uygulamanın gerçekte hangi çağrıları
yaptığını bilmek gerekiyor.

## 4. Doğrulama: "bende çalışıyor" yetmez

Kurulum temiz ortamlarda denendi: macOS'ta yeni bir venv ve Docker'da Ubuntu
26.04 ARM64 (sunucunla aynı mimari). Linux'ta iki şeyi ilk kez gerçekten
gördük: worker bellek sınırı **uygulanıyor** (40 MB'lık iş temizce
"bellek yetmedi" ile bitti, sunucu ayakta kaldı), ve `setcap` ile yetkisiz
kullanıcı **gerçek canlı yakalama** yaptı. Bu sırada Python 3.14'te çıkış
kodu 120 veren bir broken-pipe hatası da bulundu; 3.14 artık CI matrisinde.

## 5. Kontrol soruları ve deneyler

1. Host allowlist, token kullanılan uzak bir kurulumda neden hâlâ gerekli?
   (İpucu: token tarayıcıda; rebinding sayfası aynı origin olduğunda…)
2. `Origin` başlığı olmayan POST isteklerini neden reddetmiyoruz?
3. Kilit dosyası bir paketi sabitlese de bir tedarik zinciri saldırısı nasıl
   gerçekleşebilir? (İpucu: kilitleme anında zaten kötü olan bir sürüm,
   ya da derleme zamanında çalışan kod.)
4. **Deney:** `netguard serve` çalıştır ve
   `curl -H 'Host: kotu.example' localhost:8000/api/v1/captures` gönder.
   Aynısını `-H 'Origin: https://kotu.example' -X DELETE …/captures/x` ile dene.
5. **Deney (Ubuntu sunucu):** servisi kurduktan sonra
   `systemd-analyze security netguard` çalıştır. Hangi ayarlar puanı daha da
   düşürür, hangileri NetGuard'ı bozar?
