# 01 — Keşif (Reconnaissance) Tespiti: Port Tarama, Host Sweep, ARP Spoofing

> Bu not NetGuard v0.1'in tespit mantığını anlatır. Kodla birlikte oku:
> [`window.py`](../../src/netguard/window.py), [`detectors/`](../../src/netguard/detectors/).
> Sonundaki **lab görevlerini** kendin yapman bekleniyor. Cevapları
> `docs/learning/answers-01.md` dosyasına yazarsan birlikte üzerinden geçeriz.

## 1. Problem: Saldırgan önce haritayı çıkarır

Bir saldırının ilk adımı neredeyse her zaman keşiftir. Saldırgan ağda hangi
hostların canlı olduğunu (**host discovery**), bu hostlarda hangi servislerin
açık olduğunu (**port scanning**) ve trafiğin arasına girip giremeyeceğini
(**ARP spoofing / MITM**) öğrenmek ister.

Keşfi tespit etmenin değeri **erken uyarıdır**. Bu aşamada henüz bir zarar
yoktur ama niyet görünür hale gelmiştir. MITRE ATT&CK karşılıkları T1018
(Remote System Discovery), T1046 (Network Service Discovery) ve T1557.002
(ARP Cache Poisoning).

## 2. Teknik arka plan

### 2.1 TCP handshake ve tarayıcılar bunu nasıl kullanır

```
İstemci                 Sunucu
  SYN        ─────────►            "bağlanmak istiyorum"
             ◄─────────  SYN+ACK   port AÇIK
             ◄─────────  RST+ACK   port KAPALI
             (sessizlik)           FİLTRELİ (firewall paketi düşürdü)
  ACK        ─────────►            bağlantı kuruldu (connect scan)
  RST        ─────────►            yarım bırak (SYN / "half-open" scan, nmap -sS)
```

- **SYN scan (`-sS`)**: SYN gönderir, yanıta bakar, bağlantıyı RST ile
  koparır. Uygulama katmanına hiç ulaşmadığı için sunucu loglarında iz
  kalmaz. Ağ seviyesinde ise çok görünür, NetGuard'ın varlık sebebi de bu.
- **NULL / FIN / XMAS (`-sN/-sF/-sX`)**: RFC 793'e göre kapalı bir port,
  bağlantıya ait olmayan bir segmente RST ile cevap verir, açık bir port ise
  sessiz kalır. Tarayıcı bu boşluğu kullanır. Normal trafikte hiç flag'i
  olmayan (NULL) ya da FIN+PSH+URG taşıyan bir segment *görülmez*. Bu yüzden
  bu probe tipleri kendi başına güçlü bir sinyaldir ve alarm metninde
  "stealth scan" olarak vurgulanır.

`probe_type()` fonksiyonu ([portscan.py](../../src/netguard/detectors/portscan.py))
bu sınıflandırmayı yapar. İlk kural `if flags & ACK: return None`. Kurulu bir
bağlantıdaki her segment ACK taşır, dolayısıyla ACK'li hiçbir şey probe
değildir. Bu tek satır, normal trafiğin büyük kısmını ucuza eler.

### 2.2 ARP neden spoof edilebilir?

ARP (RFC 826) "IP X hangi MAC'te?" sorusunu yayınla (broadcast) sorar ve
**kimlik doğrulaması yoktur**. Kimse sormamışken gelen bir cevabı bile birçok
işletim sistemi önbelleğine yazar. Saldırgan kurbana "gateway benim" der,
gateway'e "kurban benim" der ve trafik saldırganın üzerinden akar.

Tespit fikri şu: her IP için hangi MAC'i gördüğümüzü öğreniriz. Bağlama
değişirse şüphelenir, değişimin *bağlamına* bakarak (istenmemiş cevap,
ileri-geri gidip gelme, kritik IP) önem derecesini belirleriz.

## 3. Algoritma: Kayan pencerede farklı eleman sayımı

**Soru:** "Son 60 saniyede 10.0.0.66, 10.0.0.10 üzerinde kaç *farklı* porta dokundu?"

### 3.1 Seçenekler

| Yaklaşım | Paket başına zaman | Bellek (anahtar başına) | Sorun |
|---|---|---|---|
| Sadece bir `set` | O(1) | Sınırsız büyür | **Unutmaz.** Dünkü port bugün de sayılır |
| Sabit kova (her dakika sıfırla, *tumbling window*) | O(1) | O(kova içi) | **Sınır problemi.** 59. saniyede 10, 61. saniyede 10 port → hiçbir kova 15'i görmez |
| Deque + her pakette yeniden say | O(n) | O(n) | Yavaş, tarama sırasında n büyür |
| **Deque + Counter (seçilen)** | **O(1) amortize** | O(n), üst sınırlı | Kesin sayım. Bellek pencere içindeki olay sayısı kadar |
| HyperLogLog | O(1) | O(1) (~KB) | Yaklaşık sayım, eleman *silinemez*, pencere için ek yapı gerekir |
| TRW (Threshold Random Walk) | O(1) | O(1) | Bağlantı *sonucuna* bakar, ayrı bir model (Faz 4) |

### 3.2 Nasıl çalışıyor? (`SlidingDistinct`)

```python
def add(self, ts, item):
    self._events.append((ts, item))  # deque: zaman sırasına göre olaylar
    self._counts[item] += 1  # Counter: eleman -> penceredeki tekrar sayısı
    ...
    self.evict(ts)


def evict(self, now):
    cutoff = now - self.window
    while self._events and self._events[0][0] < cutoff:
        _, old = self._events.popleft()
        self._counts[old] -= 1
        if self._counts[old] == 0:
            del self._counts[old]  # artık penceredeki hiçbir olay bu porta ait değil


def distinct(self):
    return len(self._counts)  # O(1)
```

**Neden amortize O(1)?** Her olay deque'ye *bir kez* eklenir ve *en fazla bir
kez* çıkarılır. Tek bir `add` çağrısındaki `while` döngüsü birçok eleman
silebilir, ama N olay boyunca toplam silme sayısı ≤ N'dir. Ortalama maliyet
olay başına sabittir.

**Neden sadece `set` değil de `Counter`?** Aynı porta pencere içinde iki kez
dokunulmuş olabilir. İlk olay pencereden düştüğünde port hâlâ pencerededir.
Counter bunu doğru izler. Set kullansaydık portu erken silerdik.

**Paketler zaman sırasında gelmezse?** `evict` sadece baştan siler, yani
olayların ts'ye göre sıralı geldiğini varsayar. pcap'ler genelde sıralıdır.
Küçük sıra bozuklukları (birkaç ms) sonucu pratikte değiştirmez. Bu yine de
bilinçli bir varsayım.

### 3.3 Bellek bir saldırı yüzeyidir

Girdiyi saldırgan kontrol ediyorsa, oluşturduğumuz **durumu** (state) da o
kontrol eder. Sahte kaynak IP'lerle milyonlarca anahtar yaratılabilir.
Bu yüzden:

- `max_events_per_key` olduğu için tek bir anahtarın penceresi sınırsız büyüyemez.
- `max_keys` aşılınca önce GC çalışır, yine doluysa yeni anahtar *düşürülür*
  ve `dropped_keys` artar.

Bu bir **fail-open** tercihidir: saldırı altında bazı şeyleri kaçırabiliriz
ama çökmeyiz. Çöken bir IDS hiçbir şey görmez, yani fail-closed bir IDS
aslında daha kötü bir sonuç verir.

## 4. Eşikten olaya: Incident aggregation ve alert fatigue

Eşik aşıldığında hemen alarm üretseydik `nmap` taraması 1000 portluk
taramada, eşik 15 iken onlarca alarm üretirdi. Analistler gürültülü araçları
susturur (alert fatigue). Bu yüzden `BurstTracker` eşik aşılınca bir
**Incident** açar. Incident, sonraki probe'ları ve hedefin cevaplarını
(açık/kapalı portlar) biriktirir ve `idle_timeout` kadar sessizlikten sonra
**tek** alarm olur. Ayrıntılar [ADR-0003](../adr/0003-incident-aggregation.md)'te.

Bedeli **gecikme**. Canlı modda alarm, tarama durduktan ~10 saniye sonra gelir.

## 5. Yanlış pozitif / yanlış negatif

|  | Gerçekte saldırı | Gerçekte zararsız |
|---|---|---|
| Alarm var | TP | **FP** (yanlış alarm) |
| Alarm yok | **FN** (kaçırma) | TN |

- **Precision = TP / (TP + FP)**: "Alarm verdiğimde ne sıklıkla haklıyım?"
- **Recall = TP / (TP + FN)**: "Saldırıların ne kadarını yakalıyorum?"

**Base-rate fallacy:** Gerçek bir ağda zararsız olaylar saldırılardan binlerce
kat fazladır. %99 doğru görünen bir detektör bile, saldırı nadirse,
alarmlarının çoğunu yanlış verir. Bu yüzden NetGuard'da benign *look-alike*
senaryolar (monitoring poller, passive FTP, DHCP) saldırı senaryoları kadar
önemli. Bilinen FP'leri [EVALUATION.md](../EVALUATION.md)'de saklamadan
yayınlıyoruz.

## 6. Geliştirirken karşılaştığımız hatalar (gerçek, bu repoda)

| Hata | Belirti | Kök neden | Ders |
|---|---|---|---|
| **Olay sırası** | 60 sn aralıklı 3 tarama döngüsü 1 alarm üretti | Motor önce paketi dedektöre verip *sonra* `tick` çağırıyordu. Sessizliği bitiren paket, kapanması gereken incident'ı uzattı | Akış işleme (stream processing) sistemlerinde *sıra* mantığın parçasıdır. Regresyon testi: `test_idle_gap_closes_incident_before_next_packet` |
| **`0.0` falsy** | `first_seen` yanlış çıktı | `win.first_ts or ts` → ts 0.0 olunca `or` sağ tarafı seçti | Sayısal değerlerde `or` ile varsayılan verme, `is None` kullan |
| **Import-time default** | JSONL çıktı testte yakalanmadı | `def f(stream=sys.stdout)`: varsayılan değer fonksiyon *tanımlanırken* bağlanır | Değiştirilebilir/global varsayılanları çağrı anında çöz |
| **Yanlış atıf** | ARP alarmı meşru gateway'i "src" gösterdi | Bağlama gerçek sahibine dönünce "yeni MAC" gateway'in kendisiydi | Açıklanabilirlik sadece metin değildir. Kimi suçladığın da doğru olmalı |
| **Erken cevaplar kayboldu** | Açık port 22 raporda görünmeyebilirdi | Eşikten önce gelen SYN-ACK'leri saklamıyorduk | Kanıtı eşikten *önce* de topla (`_pending`) |

## 7. Lab görevleri (senin sıran)

Görevleri sırayla yap. Kodu değiştirdiğin görevlerde önce **test yaz**.

1. **Kod okuma:** `BurstTracker.observe()` içinde incident ilk açıldığında
   `incident.events = len(win)` atanıyor. Sonraki çağrılarda ise `+= 1`
   yapılıyor. Neden ilk seferde `len(win)`? Yanlış olsaydı hangi alarm alanı
   bozulurdu?
2. **Deney (eşik):** `netguard.example.toml`'u kopyala ve
   `min_distinct_ports = 5` yap. `uv run netguard lab evaluate` komutu config
   almıyor, bu yüzden `netguard lab generate` ile pcap'leri üretip
   `netguard analyze -c` ile `benign_office` ve `passive_ftp`'yi analiz et.
   Ne değişti? Eşiği düşürmenin precision ve recall'a etkisini kendi
   cümlelerinle açıkla.
3. **Deney (kaçınma):** `slow_scan` senaryosunu yakalamak için hangi
   `window_seconds` / `min_distinct_ports` değerleri gerekir? Bu değerlerin
   bellek maliyeti nedir (en kötü durumda anahtar başına kaç olay)?
4. **Karmaşıklık:** 10 Gbit/s'lik bir ağda saniyede 1M paket geldiğini ve
   %1'inin probe olduğunu varsay. 60 sn pencere ve 100k farklı kaynakla,
   `SlidingDistinct` en kötü durumda kaç olay tutar? `max_events_per_key`
   bu sayıyı nasıl sınırlar ve bunun tespite etkisi ne olur?
5. **Protokol:** Windows hostları NULL/FIN/XMAS taramalarına RFC 793'e uymadan,
   açık portlarda da RST ile cevap verir. Bu durumda NetGuard'ın
   `open_ports` alanı ne gösterir? Detektör yine alarm üretir mi? Neden?
6. **Kod (küçük özellik):** `portscan` alarm kanıtına `probes_per_second`
   zaten ekli. Tarama hızına göre "araç tahmini" yapan bir alan ekle
   (ör. > 1000 pps → "masscan/nmap -T5 benzeri"). Önce test yaz, sonra
   uygula. Sonra kendine sor: bu alan bir analist için faydalı mı, yoksa
   yanıltıcı olabilir mi?
7. **Tasarım sorusu:** `nmap -D RND:10` (decoy) taraması aynı hedefe 11 farklı
   kaynak IP'den probe gönderir. Mevcut anahtar `(src, dst)` ise ne olur?
   Hedef-merkezli bir ek anahtar `dst` ile ne kazanır, ne kaybederiz?

<details>
<summary>İpuçları (önce kendin dene)</summary>

- (1) Pencerede eşik öncesi biriken olaylar da incident'ın parçası.
  `events` alanı alarmda `probes` ve `probes_per_second` olarak görünür.
- (4) Olay sayısı ≈ pps × probe oranı × pencere. Sınır anahtar başına
  uygulanır, anahtar sayısı ayrıca sınırlıdır.
- (5) Her port "kapalı" görünür. Detektör *yanıtlara* değil *probe'lara*
  bakarak alarm verir.
- (7) Decoy'lar sahte IP'lerdir. Gerçek tarayıcı yanıtları alabilen tek
  kaynaktır. Kimin TCP yanıtlarını gerçekten aldığına (ör. RST sonrası
  davranışa) bakmak ipucu verir.

</details>
