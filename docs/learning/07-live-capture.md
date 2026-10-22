# Öğrenme notu 07 — Canlı trafik: yetki, zaman ve gecikme

> Faz 6 · İlgili kod: `live.py`, `engine.py` (`advance`), `window.py` (`take_opened`, `max_age`)
> İlgili karar: [ADR-0010](../adr/0010-live-capture-and-alert-lifecycle.md) · Rehber: [LIVE_CAPTURE.md](../LIVE_CAPTURE.md)

## 1. En az yetki: kim root olmalı?

Ağ arayüzünü dinlemek için çekirdek yetki ister (Linux'ta `CAP_NET_RAW`,
macOS'ta `/dev/bpf*` erişimi). En kolay yol `sudo netguard ...` olurdu, ama
NetGuard ağdan gelen, saldırgan kontrollü baytları ayrıştırır. Decoder'da tek
bir hata root yetkisiyle kod çalıştırma anlamına gelirdi.

Bu yüzden yetkiyi **ayırıyoruz** (privilege separation):

- Yakalamayı `tcpdump` yapar. Yetkiyi yalnızca o alır: ya kalıcı bir
  capability (`setcap`) ya da `sudo -n tcpdump ... -Z kullanıcı`. `-Z`,
  tcpdump'ın cihazı açar açmaz kendi yetkisini bırakmasını sağlar.
- NetGuard normal kullanıcı olarak çalışır ve root olarak başlatılırsa
  **reddeder**. Açıklamalı bir hata vermek, sessizce root çalışmaktan iyidir.
- Arayüz adı doğrulanır, filtre tek bir argüman olarak verilir ve shell
  kullanılmaz. `-i 'en0; rm -rf /'` gibi bir girdi hiçbir şey çalıştıramaz.

Bu oturumda gerçek bir sınama oldu: bu Mac'te kullanıcının BPF yetkisi yok.
`netguard monitor -i lo0` gerçek tcpdump hatasını yakalayıp platforma özel
çözümü gösterdi. NetGuard'ın kendisine yetki vermek hiç gerekmedi.

## 2. Zaman: paket yoksa saat de yok mu?

Offline analizde motorun saati paketlerle ilerler: her paketin zaman damgası
"şimdi"dir. Bir tarama bitip ağ sessizleştiğinde canlı modda bir sorun çıkar:
incident'ın "10 sn sessiz kalınca kapanır" kuralı hiç tetiklenmez, çünkü
saati ilerletecek bir sonraki paket yoktur. Alarm, bir sonraki pakete kadar
(belki saatlerce) bekler.

Çözüm `Engine.advance(now)`. Kuyruk bir saniye boş kalınca ana döngü saati
paket olmadan ilerletir. İki incelik var:

1. **Saat kaydırması (offset):** ilk pakette `paket_zamanı − monotonic_zaman`
   farkı kaydedilir. Böylece hem canlı trafik hem de eski bir pcap'in replay'i
   aynı kodla çalışır. Replay'de saat hıza göre ölçeklenir (`--speed 10`).
2. **Bir saniye geriden gelmek:** saat, kuyrukta hâlâ bekleyen bir paketin
   zamanını geçerse o paket "geçmişten" gelir ve kapanmış bir incident'ı yeni
   bir incident olarak yeniden açabilir. Saat bu yüzden gerçek zamanın bir
   saniye gerisinde tutulur. Testler replay'in son alarmlarının offline
   analizle **birebir aynı** olduğunu doğruluyor.

Motor tek thread'de kalır: yakalama ayrı bir thread'de çalışır ve sınırlı bir
kuyruğa yazar. Kuyruk dolarsa okuyucu bekler, tcpdump'ın tamponu dolar ve
çekirdek paket düşürür. Bellek büyümez, kayıp ise tcpdump istatistiğiyle
(`dropped by kernel`) **raporlanır**. Bu bir fail-open tercihidir: kaybı
saklamıyoruz ama çökmüyoruz da.

## 3. Gecikme: kanıt mı hız mı?

ADR-0003 incident'ları sessizleşince raporluyordu: kanıt eksiksiz, gürültü az.
Canlı modda bunun bedeli ağır olabilir. Analist taramayı ancak tarama bitince
öğrenir, hiç durmayan bir tarama ise hiç raporlanmaz.

İki mekanizma eklendi:

| Mekanizma | Ne yapar | Bedeli |
|---|---|---|
| **Erken uyarı** (`stage: "early"`) | Eşik aşılınca hemen, eldeki kanıtla bir alarm üretir; incident kapanınca `final` gelir. İkisi aynı `alert_id`'yi paylaşır | Kanıt eksik; sonradan bastırılan bir incident (ör. portların çoğu açık çıktı) final alarm üretmeyebilir |
| **Azami yaş** (`max_incident_age_seconds`) | Çok uzun süren incident'ı kapatıp raporlar, aktivite sürerse yenisini açar | Tek bir uzun saldırı birden fazla alarma bölünür |

Ölçülen tespit gecikmeleri ([EVALUATION.md](../EVALUATION.md#detection-delay)):
hızlı taramalar ve sweep'ler ~1–2 sn, SYN flood ~11 sn (10 sn'lik aralık),
DNS tünelleme ~20 sn (50 benzersiz alt alan adı gerekiyor), yavaş tarama
76 sn (6 başarısız deneme × 15 sn), baseline kuralları ~60 sn (dakikalık
aralık). Her sayı kuralın tasarımından doğrudan çıkıyor. Gecikmeyi düşürmek
neredeyse her zaman daha az kanıtla karar vermek, yani daha fazla yanlış
pozitif demek.

## 4. Kontrol soruları ve deneyler

1. Neden `tcpdump -i any` yerine tek bir arayüz şart koşuyoruz? (İpucu: yetki
   sınırı ve Linux SLL link tipi.)
2. `Engine.advance` saati geriye almıyor. Saat geriye alınabilseydi hangi
   hata oluşurdu?
3. Kuyruk sınırını 10 000 yerine sınırsız yapsaydık yüksek trafikte ne olurdu?
   Hangisi daha iyi bir hata modu: bellek tükenmesi mi, raporlanan paket kaybı mı?
4. Erken uyarı ve final alarm aynı `alert_id`'yi taşıyor. Bir SIEM bu iki
   olayı nasıl birleştirmeli?
5. **Deney (lab):** Ubuntu'da `netguard monitor -i <arayüz> --write live.pcap`
   çalıştırırken Kali'den `nmap -sS -T4` ve ardından `nmap -sS -T1 -p 1-30`
   gönder. Erken uyarılar ne zaman geliyor? Sonra
   `netguard analyze live.pcap` ile final alarmları karşılaştır.
6. **Deney:** `netguard replay` ile `slow_scan` lab yakalamasını `--speed 10`
   ve `--speed 100` hızlarında oynat. Raporlanan gecikme neden farklı?
   (İpucu: boşta saat ilerletme adımı.)
