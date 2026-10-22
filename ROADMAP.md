# NetGuard Yol Haritası

> Son güncelleme: **2026-10-22** · Mevcut sürüm: **v0.2.0** · Aktif faz: **Faz 3 — Tespit motoru**
>
> Bu dosya projenin **tek** yol haritasıdır. Güncel iş listesi
> [docs/TASKS.md](docs/TASKS.md), ölçülmüş sonuçlar
> [docs/EVALUATION.md](docs/EVALUATION.md), mimari kararlar [docs/adr/](docs/adr/)
> altındadır.

Durum: ✅ tamamlandı · 🔄 devam ediyor · ⏳ başlanmadı · 👤 kullanıcı gerekli
(fiziksel lab, hesap ayarı veya yayın onayı).

---

## 1. Ürün vizyonu ve kapsam

**NetGuard**, ağ trafiğini (pcap/pcapng, kontrollü canlı yakalama) analiz eden,
paket/bağlantı/protokol özelliklerini çıkaran, şüpheli davranışı
**açıklanabilir kurallarla** tespit eden, her alarmı kanıtıyla birlikte
yapılandırılmış olarak üreten ve sonuçları bir web dashboard'da gösteren bir
ağ güvenliği izleme ve analiz platformudur.

**NetGuard'ı farklı kılan:**

1. **Açıklanabilirlik:** her alarm ne görüldüğünü, hangi eşiğin aşıldığını,
   saldırganın ne öğrendiğini ve ATT&CK karşılığını söyler. Kesinlik yerine
   kanıtın desteklediği ifade kullanılır ("possible ARP spoofing").
2. **Ölçülebilirlik:** tespit kalitesi etiketli senaryolar ve lab yakalamalarıyla
   ölçülür, sonuçlar (yanlış pozitifler dahil) yayınlanır.
3. **Saldırgan girdiye dayanıklılık:** her bayt düşmanca kabul edilir, tüm
   durum (state) sınırlıdır, sınır işlemleri O(1)'dir.
4. **Okunabilirlik:** küçük, test edilmiş, belgelenmiş bir kod tabanı.

**Kapsam dışı (bilinçli olarak):** satır hızında (10 Gbit/s) yakalama, inline
engelleme (IPS), imza tabanlı exploit tespiti, tam protokol ayrıştırma. Bunları
Zeek ve Suricata zaten iyi yapıyor; NetGuard onlarla özellik özellik yarışmaz,
ileride onların çıktılarını ek girdi olarak okuyabilir.

**Donanım hedefi:** MacBook Air M1 (geliştirme), Kali (UTM, saldırgan), ~4 GB
RAM'li Ubuntu sunucu (kurban / dağıtım hedefi). Bulut, ücretli API ve
mikroservis yok.

## 2. Mevcut durum (2026-10-22)

| Faz | Konu | Durum | Sürüm |
|---|---|---|---|
| 0 | Araştırma, mimari, temel | ✅ | v0.1.0 |
| 1 | Paket alma ve protokol analizi | ✅ | v0.1.0 + v0.2.0 |
| 2 | Flow ve özellik çıkarımı | ✅ | **v0.2.0** |
| 3 | Tespit motoru (genişletme) | 🔄 | v0.3.0 |
| 4 | Backend, kalıcılık, API | ⏳ | v0.4.0 |
| 5 | Web dashboard | ⏳ | v0.5.0 = **MVP** |
| 6 | Canlı yakalama ve replay | ⏳ | v0.6.0 |
| 7 | İleri tespit ve tehdit istihbaratı | ⏳ | v0.7.0 |
| 8 | Test, benchmark, değerlendirme | 🔄 sürekli · 👤 lab | v0.8.0 |
| 9 | Güvenlik sertleştirme ve CI/CD | 🔄 sürekli | v0.9.0 |
| 10 | Dokümantasyon, release, portföy | ⏳ | **v1.0.0** |

**Ölçülmüş durum (v0.2.0):** 161 test, kapsama %94,8; ruff, mypy `--strict`
temiz; 242k paketlik referans pcap ~2,2 sn / 35 MB (M1, ~110k paket/s);
sahte kaynaklı 500k flow saldırısında tepe bellek 349 MB. Ayrıntı:
[EVALUATION.md §3](docs/EVALUATION.md#3-performance).

**Gerçek dünyada doğrulama yok:** tüm tespit sonuçları şimdilik sentetik
senaryolardan. Lab yakalamaları (Faz 8) kullanıcının UTM ortamını gerektirir.

## 3. Fazlar arası bağımlılık

```mermaid
flowchart LR
    F0[0 ✅ Temel] --> F1[1 ✅ Paket alma]
    F1 --> F2[2 ✅ Flow]
    F2 --> F3[3 🔄 Tespit motoru]
    F3 --> F4[4 Backend & API]
    F4 --> F5[5 Dashboard<br/>= MVP]
    F4 --> F6[6 Canlı & replay]
    F5 --> F6
    F3 --> F7[7 İleri tespit]
    F4 --> F7
    F8[8 Değerlendirme<br/>sürekli] -.-> F3
    F8 -.-> F7
    F9[9 Sertleştirme & CI<br/>sürekli] -.-> F4
    F6 --> F10[10 Release v1.0]
    F7 --> F10
    F8 --> F10
    F9 --> F10
```

Faz 8 ve 9 her fazda sürekli yürütülür (her dedektör senaryo ve testle gelir,
her değişiklik CI'dan geçer); kendi fazlarında eksikler toplanıp tamamlanır.

**MVP (v0.5.0):** pcap yükle → analiz et → flow'ları, istatistikleri ve
kanıtlı alarmları dashboard'da incele → rapor/olay dışa aktar. Tüm tespitler
sentetik senaryolarda ölçülmüş, sınırlamalar belgelenmiş.

## 4. Çalışma yöntemi

Her faz için: gereksinim ve bağımlılık gözden geçirme → işlere bölme →
uygulama → test → hata düzeltme → doküman → commit/push → kabul kriterleri
karşılanınca faz kapanışı.

Her önemli algoritma ve güvenlik mekanizması için bir **öğrenme kontrol
noktası** vardır: problem, çözüm, neden bu çözüm, alternatifler, karmaşıklık,
sınırlamalar ve kısa deney/sorular. Bunlar `docs/learning/NN-*.md` (Türkçe)
notlarında toplanır.

Kurallar: her yeni dedektör bir saldırı senaryosu, bir **benign benzeri**
senaryo ve birim testlerle gelir; performans gerilemesi %20'yi geçemez;
ölçülmemiş sonuç yazılmaz; büyük kararlar ADR ile belgelenir.

---

## 5. Fazlar

### Faz 0 — Araştırma, mimari ve temel ✅

Kapsam analizi, Python + dpkt seçimi ([ADR-0001](docs/adr/0001-python-and-dpkt.md)),
canlı yakalamanın `tcpdump`'a devri ([ADR-0002](docs/adr/0002-capture-via-tcpdump.md)),
incident birleştirme ([ADR-0003](docs/adr/0003-incident-aggregation.md)), `uv`,
ruff, mypy `--strict`, pytest, CI (Linux/macOS × Python 3.11–3.13), MIT lisansı,
AI co-author trailer'larını reddeden `commit-msg` hook'u, SSH imzalı commit'ler.

### Faz 1 — Paket alma ve protokol analizi ✅

| # | İş | Durum |
|---|---|---|
| 1.1 | pcap/pcapng okuma, stdin dahil seek edilemeyen akışlar | ✅ v0.1 |
| 1.2 | Decoder: Ethernet, Linux SLL, BSD loopback, raw IP; IPv4/IPv6; TCP/UDP/ICMP/ICMPv6/ARP; DNS sorgu adı | ✅ v0.1 |
| 1.3 | Bozuk paketler sayılır, hata fırlatılmaz; fuzz testi | ✅ v0.1 |
| 1.4 | CLI: `analyze` (text/JSON/JSONL), `lab` | ✅ v0.1 |
| 1.5 | **Kendi pcap/pcapng okuyucuları:** çok arayüzlü pcapng (arayüz başına link tipi, `if_tsresol`), uzunluk alanı sınırları, kesik dosya raporlama ([ADR-0005](docs/adr/0005-own-capture-readers-and-fast-decoder.md)) | ✅ v0.2 |
| 1.6 | Decoder: TCP seq/ack, payload uzunluğu (IP uzunluğundan, snaplen'e dayanıklı), TTL, IP fragment işareti | ✅ v0.2 |
| 1.7 | `struct` tabanlı hızlı decode yolu + dpkt ile diferansiyel fuzz testi | ✅ v0.2 |
| 1.8 | Paket boyutu dağılımı, desteklenmeyen link tipi sayacı | ✅ v0.2 |

**Kabul kriterleri:** ✅ bozuk girdiyle çökmeme (fuzz), ✅ sınırlı bellek (düşmanca
uzunluk alanları testli), ✅ çok arayüzlü pcapng testli, ✅ CLI testli.

**Bilinen sınırlama:** IP fragment birleştirme yok (fragment'lar işaretlenir ve
sayılır); IPv6 extension header'lı paketlerde payload uzunluğu yakalanan
bayttan hesaplanır.

### Faz 2 — Flow ve özellik çıkarımı ✅ (v0.2.0)

| # | İş | Durum |
|---|---|---|
| 2.1 | Çift yönlü flow, originator tespiti (SYN-ACK ile yön düzeltme) | ✅ |
| 2.2 | Yön bazlı paket/bayt/payload sayaçları, süre, TCP bayrak birikimi, Zeek tarzı `history` | ✅ |
| 2.3 | Zeek uyumlu `conn_state` (S0, S1, SF, REJ, S2, S3, RSTO, RSTR, RSTOS0, RSTRH, SH, SHR, OTH) | ✅ |
| 2.4 | Retransmission ve sequence gap tespiti (RFC 1982 serial aritmetik) | ✅ |
| 2.5 | Zaman aşımı sınıfları ve O(1) expiry; port yeniden kullanımı; LRU eviction ([ADR-0004](docs/adr/0004-flow-semantics.md)) | ✅ |
| 2.6 | Dedektörlere `on_flow_end(flow)` kancası | ✅ |
| 2.7 | `netguard flows -f csv\|jsonl` | ✅ |
| 2.8 | İstatistikler: flow durum dağılımı, servisler, en büyük flow'lar, uyarlanabilir zaman serisi, sınırlı endpoint tablosu | ✅ |
| 2.9 | Alarm modeli v1: `rule_id`, deterministik `alert_id`, `schema_version`; sözleşme testi; [kural kataloğu](docs/rules/README.md) | ✅ |
| 2.10 | Tracker DoS düzeltmesi: dolu tabloda O(n) GC → O(1) LRU; anahtar başına bellek 1 996 → 668 bayt | ✅ |
| 2.11 | Gerçek lab yakalamasında `nmap -sS` durum dağılımı, Zeek `conn.log` karşılaştırması | 👤 Faz 8'e taşındı |

**Kabul kriterleri:** ✅ `flows` komutu çalışıyor, ✅ her TCP durumu el yapımı
paket dizisiyle test edildi, ✅ tüm alarmlarda `rule_id`/`schema_version`,
✅ performans gerilemesi yok (v0.1'den ~1,6× hızlı), ✅ sentetik sonuçlar v0.1
ile aynı (bilinçli incident düzeltmesi hariç). Lab doğrulaması 👤 Faz 8'de.

**Öğrenme notu:** [02 — Paketten bağlantıya](docs/learning/02-flows-and-tcp-state.md).

### Faz 3 — Tespit motoru 🔄 (v0.3.0)

**Amaç:** istenen tespit kategorilerinin tamamını, her biri için gözlenebilir
davranış, mantık, eşik, kanıt, test ve FP/FN belgesiyle tamamlamak.

| # | İş | Kategori |
|---|---|---|
| 3.1 | DNS decoder genişlemesi: tüm sorular, `qtype`, yanıt, `rcode`, cevap sayısı, ID ile sorgu-yanıt eşleştirme; DNS istatistikleri | DNS |
| 3.2 | **TRW tarama dedektörü** (Jung vd., 2004): flow sonuçlarıyla (SF vs S0/REJ) ardışık hipotez testi; pencere tabanlı dedektörle karşılaştırma ve ADR. `passive_ftp` FP'sini hedefler | Port tarama |
| 3.3 | UDP tarama: ICMP port-unreachable'ı "kapalı port" sinyali olarak kullanma | Port tarama |
| 3.4 | Yavaş tarama: uzun ufuklu, düşük eşikli ikinci pencere; bellek bütçesi | Port tarama |
| 3.5 | **SYN flood:** hedef `ip:port` başına S0 oranı ve SYN hızı, kaynak çeşitliliği (spoofing göstergesi). T1499.001 | SYN |
| 3.6 | ICMP anomalileri: anormal tip/kod dağılımı, büyük/fragment'lı ICMP, ICMP hızı | ICMP |
| 3.7 | DNS anomalileri: tünelleme göstergeleri (label uzunluğu, entropi, alt domain sayısı, TXT oranı), NXDOMAIN/DGA oranı, onaysız resolver | DNS |
| 3.8 | Olağan dışı bağlantı sıklığı: kaynak başına yeni flow hızı (EWMA baseline + robust sapma) | Bağlantı |
| 3.9 | Olağan dışı trafik hacmi: host başına bps/pps sapması ("normalin N katı") | Hacim |
| 3.10 | Fragment anomalisi: küçük/çakışan fragment'lar (`nmap -f` göstergesi) | Diğer |
| 3.11 | Her kural için senaryo + benign benzeri + `docs/rules/<rule_id>.md` | Hepsi |
| 3.12 | Kural yapılandırması: kural bazında aç/kapa ve eşikler TOML'da; kural listesi CLI'da (`netguard rules`) | Motor |

**Kabul kriterleri:** her kategori için en az bir kural; her kural saldırı ve
benign senaryoda test edilmiş; kural sayfaları FP/FN ve ayar önerisi içeriyor;
skor tablosu güncel; şüphe ifadesi kanıta uygun.

**Öğrenme notları:** 03 TRW ve ardışık hipotez testi; 04 DNS kötüye kullanımı,
entropi ve robust istatistik.

### Faz 4 — Backend, kalıcılık ve API ⏳ (v0.4.0)

| # | İş |
|---|---|
| 4.1 | Teknoloji kararı (ADR): aday SQLite (stdlib) + FastAPI; çekirdek bağımlılıksız kalır (`netguard[web]`) |
| 4.2 | Şema: `captures`, `analysis_jobs`, `flows`, `alerts`, `rules`, `stats`; sürümlü migrasyon |
| 4.3 | İş yaşam döngüsü: `queued → running → done/failed`, iptal, hata kaydı, kesilen işlerin kurtarılması |
| 4.4 | API v1: yükleme, analiz, flow/alarm arama, sıralama, filtreleme, sayfalama; OpenAPI dokümanı |
| 4.5 | Olay şeması: SIEM entegrasyonu için sürümlü JSON (ECS eşlemesi) |
| 4.6 | Entegrasyon testleri (`TestClient`), yükleme boyut/tür sınırları |

### Faz 5 — Web dashboard ⏳ (v0.5.0 = MVP)

| # | İş |
|---|---|
| 5.1 | Teknoloji kararı (ADR): sunucu tarafı render + htmx ile React/Vite SPA karşılaştırması |
| 5.2 | Güvenlik özeti, trafik istatistikleri, protokol dağılımı, flow ve endpoint görünümleri |
| 5.3 | Alarm akışı, alarm detayı ve kanıt görünümü, kural sayfalarına bağlantı |
| 5.4 | pcap yükleme ve analiz iş akışı; yükleme, boş ve hata durumları |
| 5.5 | Kural yönetimi; rapor (HTML/JSON) ve dışa aktarma |
| 5.6 | Pcap'ten gelen tüm stringler için XSS testi; yalnızca gerçek veri, sahte metrik yok |

### Faz 6 — Canlı yakalama ve replay ⏳ (v0.6.0)

| # | İş |
|---|---|
| 6.1 | `netguard monitor`: yetkili arayüzde `tcpdump` alt süreci, `-Z` ile yetki düşürme, başlat/durdur, kaynak sınırları |
| 6.2 | macOS/Linux izin farkları ve sınırlamaların belgelenmesi |
| 6.3 | Kaydedilmiş yakalamaların kontrollü replay'i ve farklı konfigürasyonla yeniden analiz |
| 6.4 | Alarm yaşam döngüsü: eşikte **erken uyarı**, incident sonunda nihai alarm, `max_incident_age` |
| 6.5 | Canlı = offline doğrulaması (`tcpreplay`, 👤 lab); 24 saatlik soak testi, paket kaybı ölçümü |

### Faz 7 — İleri tespit ve tehdit istihbaratı ⏳ (v0.7.0)

Her özellik ölçülebilir değerine göre seçilir. Adaylar: davranışsal baseline,
alarm tekilleştirme ve korelasyon (decoy tarama, DHCP korelasyonuyla ARP FP
azaltma), açıklanabilir güven/şiddet puanı, beaconing ve veri sızdırma,
Zeek `conn.log`/Suricata EVE JSON girdisi, kural içe/dışa aktarma, offline
IoC listeleri. ML yalnızca somut ve ölçülmüş bir kullanım durumu varsa.

### Faz 8 — Test, benchmark ve değerlendirme 🔄 sürekli · 👤 lab

| # | İş | Durum |
|---|---|---|
| 8.1 | Etiketli sentetik senaryolar, `lab evaluate`, CI'da skor tablosu | ✅ |
| 8.2 | Tekrarlanabilir benchmark'lar (`benchmarks/`), flood bellek testi | ✅ v0.2 |
| 8.3 | UTM lab: Kali → Ubuntu, izole host-only ağ ([LAB_SETUP.md](docs/LAB_SETUP.md)) | 👤 |
| 8.4 | Saldırı yakalamaları (`nmap` tipleri ve zamanlamaları, `masscan`, `arp-scan`, `bettercap`) ve ≥ 1 saat benign trafik | 👤 |
| 8.5 | Yakalama manifestosu (`eval/captures.toml`: sha256, araç, komut, beklenen alarm); `lab evaluate --manifest` | ⏳ |
| 8.6 | Precision/recall, benign trafikte saat başına alarm, tespit gecikmesi; açık veri setleri (lisansına uygun) | ⏳ |
| 8.7 | Kesilen iş, bozuk girdi, uzun çalışma senaryoları | ⏳ |

### Faz 9 — Güvenlik sertleştirme ve CI/CD 🔄 sürekli

Girdi doğrulama, yükleme/kaynak/zaman aşımı/depolama sınırları, API ve
dashboard erişim kontrolü (varsayılan `127.0.0.1`), gizli bilgi ve yakalama
verisinin sızmaması, bağımlılık lisans ve güvenlik taraması (`pip-audit`),
statik analiz (ruff `S` kuralları mevcut), GitHub Actions, kurulum/dağıtım
doğrulaması.

### Faz 10 — Dokümantasyon, release ve portföy ⏳ (v1.0.0)

Kod kalitesi incelemesi, mimari ve operasyon dokümanları, kurulum ve
geliştirici rehberi, gerçek demo ve ekran görüntüleri, desteklenen protokoller
ve tespit sınırlamaları, mühendislik değerlendirme raporu, CHANGELOG ve
release notları, GitHub release'i (👤 yayın onayı), LinkedIn portföy metni
taslağı.

**v1.0 tamamlanma tanımı:** brief'teki "Definition of Done" maddelerinin
hepsi kanıtla karşılanmış; karşılanamayan madde varsa açıkça yazılır ve tam
uyum iddia edilmez.

---

## 6. Teknoloji kararları

| Alan | Karar | Durum |
|---|---|---|
| Dil | Python 3.11+ (okunabilirlik, test edilebilirlik; performans ölçülerek yönetiliyor) | ADR-0001 |
| Paket ayrıştırma | Kendi pcap/pcapng okuyucuları + `struct` hızlı yol + dpkt yedek | ADR-0005 |
| Canlı yakalama | `tcpdump`/`dumpcap` alt süreci; NetGuard root çalışmaz | ADR-0002 |
| Alarm modeli | Incident birleştirme, `rule_id`, deterministik `alert_id`, şema 1.0 | ADR-0003 |
| Flow modeli | Zeek `conn_state` sözlüğü, zaman aşımı sınıfları, LRU | ADR-0004 |
| Depolama | SQLite (aday) | Faz 4 ADR |
| API | FastAPI (aday) | Faz 4 ADR |
| Dashboard | htmx vs React/Vite | Faz 5 ADR |

## 7. Test stratejisi

| Seviye | Ne | Araç | Ne zaman |
|---|---|---|---|
| Birim | Decoder, okuyucular, flow durumları, pencereler, dedektörler | pytest, el yapımı `Packet`/frame | Her commit (CI) |
| Diferansiyel | Hızlı decode yolu = dpkt yolu | 5 000 mutasyonlu frame | Her commit |
| Senaryo | Saldırı + benign benzeri; TP/FP/FN sabitlenmiş | `lab/scenarios.py` | Her commit |
| Dayanıklılık | Bozuk frame/dosya, düşmanca uzunluklar, flood bellek | `test_decode`, `test_formats`, `benchmarks/` | Her commit / release |
| Gerçek yakalama | Gerçek araç davranışı, benign FP oranı | Manifesto + yerel pcap'ler (git dışı) | Dedektör değişikliklerinde 👤 |
| Performans | Throughput, RSS; gerileme < %20 | `benchmarks/make_bench_pcap.py` | Her faz sonu |
| API/Web | Sözleşme, yükleme güvenliği, XSS | `TestClient` | Faz 4–5'ten itibaren |

Kapsama eşiği %90 (CI'da zorunlu). Gerçek pcap'ler git'e girmez (`.gitignore`).

## 8. Bilinen sorunlar

| Sorun | Etki | Hedef |
|---|---|---|
| Sonuca bakmayan SYN sayımı | `passive_ftp` FP | 3.2 TRW |
| Sabit 60 sn pencere | `slow_scan` kaçıyor | 3.4 |
| UDP tarama tespiti yok | `nmap -sU` görünmüyor | 3.3 |
| Tek ARP bağlama değişikliği alarm üretiyor | `dhcp_reassignment` FP | Faz 7 (DHCP korelasyonu) |
| İzleme sunucusu ping sweep gibi görünüyor | `monitoring_poller` FP (allowlist ile çözülüyor) | Faz 7 (baseline) |
| Decoy/sahte kaynaklı taramalar | Bir tarama birçok kaynağa bölünüyor | Faz 7 |
| Idle-timeout gecikmesi | Canlı alarmlar ≥ 10 sn gecikiyor | 6.4 |
| IP fragment birleştirme yok | `nmap -f` probe'ları TCP olarak ayrıştırılmıyor | 3.10 |
| Dedektör `max_keys` TOML'dan ayarlanamıyor | 4 GB sunucuda bellek ayarı yalnız `max_flows` ile | 3.12 |

## 9. Kullanıcı gerektiren işler 👤

- UTM lab kurulumu ve gerçek yakalamalar (8.3, 8.4); yalnızca sahip olunan,
  izole ağda.
- GitHub: repo görünürlüğünü değiştirmek (şu an private), release yayınlamak.
- Canlı yakalama testleri için yetkili arayüz seçimi ve `sudo`.

## 10. Bu dosyanın bakımı

- İş bitince durum burada, ayrıntı [docs/TASKS.md](docs/TASKS.md)'de güncellenir.
- Faz bitince §2 ve değişiklik kaydı güncellenir, CHANGELOG'a sürüm eklenir.
- Plan değişirse nedeni bir satırla aşağıya yazılır; mimari etkisi varsa ADR açılır.

### Değişiklik kaydı

- **2026-10-22:** Yol haritası, proje brief'indeki 0–10 faz yapısına göre
  yeniden düzenlendi. Eski Faz 2 (lab) → Faz 8; eski Faz 3 (flow) → Faz 2;
  eski Faz 4–5 (tarama, SYN flood, DNS, hacim) → Faz 3; eski Faz 6–7 (rapor,
  API, dashboard) → Faz 4–5; eski Faz 8 (canlı) → Faz 6; eski Faz 9–10 →
  Faz 7. MVP, dashboard dahil olacak şekilde v0.5.0 olarak yeniden tanımlandı.
  Faz 2 tamamlandı (v0.2.0).
- **2026-10-21:** Yol haritası Türkçe olarak yeniden yazıldı, mevcut durum analizi eklendi.
- **2026-10-20:** Faz 0–1 tamamlandı (v0.1.0).
