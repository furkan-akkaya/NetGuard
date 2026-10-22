# Öğrenme notu 02 — Paketten bağlantıya: flow takibi ve TCP durumu

> Faz 2 · İlgili kod: `flows.py`, `stats.py`, `formats.py`, `window.py`
> İlgili kararlar: [ADR-0004](../adr/0004-flow-semantics.md), [ADR-0005](../adr/0005-own-capture-readers-and-fast-decoder.md)

## 1. Problem: paket seviyesi neden yetmiyor?

v0.1'deki port tarama dedektörü "bir kaynak 60 saniyede kaç farklı porta SYN
gönderdi?" diye soruyordu. Bu soru bağlantının **sonucunu** bilmez. Pasif FTP
istemcisi de 25 farklı porta SYN gönderir, ama her bağlantı **başarılı** olur.
Tarayıcının bağlantıları ise çoğunlukla yanıtsız kalır ya da RST ile reddedilir.
Aradaki fark paketlerde değil, *bağlantılarda* görünür.

Sonraki dedektörlerin hepsi bağlantı seviyesinde sorular soruyor:

| Soru | Dedektör |
|---|---|
| Bağlantı kuruldu mu, reddedildi mi, yanıtsız mı kaldı? | TRW tarama tespiti, SYN flood |
| Hangi yönde kaç bayt gitti? | Veri sızdırma |
| Bağlantı başlangıçları ne kadar düzenli? | C2 beaconing |

## 2. Flow nedir?

Aynı 5-tuple'ı `(protokol, kaynak IP, kaynak port, hedef IP, hedef port)`
paylaşan paketler, **iki yönde de**, tek bir flow'dur. `A:40000 → B:80` ve
`B:80 → A:40000` aynı bağlantının iki yüzüdür. Bunu O(1) yapmak için anahtarı
kanonik hale getiriyoruz: iki uç noktayı sıralayıp küçük olanı başa koyuyoruz.

```python
a, b = (src_ip, src_port), (dst_ip, dst_port)
lo, hi = (a, b) if a <= b else (b, a)
key = (proto, *lo, *hi)  # iki yön de aynı anahtarı üretir
```

**Originator (başlatan)** ilk paketi gönderen taraftır. Bir istisna var: ilk
gördüğümüz TCP paketi SYN-ACK ise SYN'i kaçırmışızdır (yakalama bağlantının
ortasında başlamış). SYN-ACK'i gönderen sunucudur, yön ters çevrilir.

## 3. TCP bağlantı durumu: neden tam bir durum makinesi değil?

RFC 9293'teki TCP durum makinesi (`SYN-SENT`, `ESTABLISHED`, `TIME-WAIT`…)
**uç noktanın** kendi durumudur. Biz pasif bir gözlemciyiz: bir paketi
gördüğümüz, karşı tarafın onu aldığı anlamına gelmez (yolda kaybolmuş
olabilir). Tam durum makinesi bize sahip olmadığımız bir kesinlik vaat ederdi.

Bunun yerine Zeek'in yaptığını yapıyoruz: her yönde görülen TCP bayraklarını
OR'layarak biriktiriyoruz ve durumu bu iki sayıdan türetiyoruz.

| Durum | Anlamı | Tipik neden |
|---|---|---|
| `S0` | SYN var, yanıt yok | Filtrelenmiş port, kapalı host, SYN flood |
| `REJ` | SYN'e RST ile yanıt | Kapalı port |
| `RSTO` | Kuruldu, başlatan RST ile kesti | **Half-open SYN taraması açık porta** (`nmap -sS`) |
| `SF` | Kuruldu ve iki yönde FIN ile kapandı | Normal bağlantı |
| `S1` | Kuruldu, kapanmadı | Hâlâ açık bağlantı |
| `OTH` | SYN görülmedi | Yakalama bağlantının ortasında başladı |

Tam liste ve öncelik sırası ADR-0004'te. Lab senaryosunda `syn_scan_1000`
için çıktı şu: `Flow states: REJ 997, RSTO 3`. 997 kapalı port reddedildi;
3 açık port (22, 80, 443) SYN-ACK döndü ve `nmap` bağlantıyı RST ile kesti.
`passive_ftp` için ise `SF 26`: hepsi başarılı. Faz 3'teki TRW dedektörü tam
olarak bu farkı kullanacak.

**Neden bayrak birikimi iyi bir seçim?** O(1) bellek (iki tamsayı), sıradan
bağımsız (küçük paket sıra bozulmalarından etkilenmez) ve planlanan her
dedektör için yeterli. Bedeli: `SYN → RST → SYN-ACK` gibi tuhaf sıraları
ayırt edemez. Bu nadir durumlar belgelenmiş bir sınırlama.

## 4. Retransmission tespiti ve 32-bit aritmetik

TCP sıra numarası 32 bittir ve taşar: `4 294 967 295`'ten sonra `0` gelir.
"`a`, `b`'den sonra mı?" sorusu normal `>` ile sorulamaz. RFC 1982 serial
aritmetiği:

```python
def seq_after(a, b):
    diff = (a - b) % 2**32
    return 0 < diff < 2**31  # farkı "yarım daireden" küçükse a ileridedir
```

Her yön için şimdiye kadar görülen en yüksek `seq + uzunluk` değerini
tutuyoruz. Yeni segmentin sonu bu değeri geçmiyorsa **retransmission**, başı
bu değerin ilerisindeyse **gap** (kayıp, sıra bozulması ya da yakalamanın
kendisinin paket düşürmesi). Dürüst olmamız gereken nokta: gözlemci geç gelen
bir sıra dışı paketi retransmission'dan ayıramaz, ikisi de aynı sayaca gider.

Uzunluğu IP başlığındaki *toplam uzunluktan* hesaplıyoruz, yakalanan bayt
sayısından değil. `tcpdump -s 96` ile kesilmiş bir yakalamada yakalanan
payload 30 bayt olabilir ama gerçek payload 1000 bayttır. Yakalanan uzunluğu
kullansaydık her segmentten sonra sahte bir gap görürdük.

## 5. Flow'lar ne zaman biter? O(1) expiry

Bir flow kapanınca (FIN/RST), boşta kalınca (idle timeout) veya bellek dolunca
biter. Zaman aşımları duruma göre farklıdır: yanıtsız bir SYN için 30 sn,
kurulmuş bir TCP bağlantısı için 300 sn, kapanmış bağlantı için 5 sn.

**Naif çözüm:** her saniye tüm flow'ları tara, süresi dolanları sil.
200 000 flow ve 1 saatlik bir pcap için bu 3600 × 200 000 = 720 milyon
kontrol demek. Offline analizde pcap'i gerçek zamandan çok daha hızlı
okuduğumuz için bu maliyet doğrudan hıza yansır.

**Kullandığımız çözüm:** her *zaman aşımı sınıfı* için ayrı bir
`OrderedDict`, son güncellenme sırasına göre. Bir sınıftaki tüm flow'ların
zaman aşımı aynı olduğundan, listenin başındaki flow her zaman ilk süresi
dolacak olandır. Expiry baştan siler ve ilk canlı flow'da durur:

```text
sınıf "kurulmuş TCP" (300 sn):  [en eski] f7 → f2 → f9 → ... → f4 [en yeni]
expire(now):  f7 doldu mu? evet → sil;  f2 doldu mu? hayır → DUR
```

Her flow en fazla bir kez silinir, yani maliyet flow başına **amortize O(1)**.
Bir paket geldiğinde flow `move_to_end` ile sona taşınır (O(1)). Durumu
değişen flow (yanıtsız → kurulmuş) bir listeden diğerine O(1) ile geçer.

## 6. Bellek bir saldırı yüzeyidir (yine)

Not 01'de söylediğimiz gibi: girdiyi saldırgan kontrol ediyorsa, oluşturduğumuz
durumu da o kontrol eder. Bu fazda iki gerçek sorun bulduk ve düzelttik.

**1. Tablo dolunca O(n) tarama.** `BurstTracker` anahtar sınırına (100 000)
ulaştığında, her *yeni* kaynak için tüm pencereleri tarayan bir GC
çalıştırıyordu. Sahte kaynak IP'li bir SYN flood'da her paket 100 000 işlem
demekti. 500 000 paketlik flood testi 2 dakikada bitmedi. Çözüm flow tablosuyla
aynı fikir: pencereleri son kullanım sırasında tutmak, GC'yi baştan yapıp ilk
canlı anahtarda durmak, tablo doluysa en eski anahtarı O(1) ile çıkarmak.
Sonuç: aynı test 8,7 saniye, ~57k paket/s.

**2. Anahtar başına bellek.** CPython'da boş bir `deque` 760 bayt yer kaplar.
Her sahte kaynak için bir pencere ve bir "bekleyen incident" nesnesi vardı,
anahtar başına ~2 KB. Pencereyi "liste + baş indeksi" yapısına çevirdik
(baştan silme indeksi ilerletir; tüketilen kısım listenin yarısını geçince
tek seferde silinir, yine amortize O(1)). Bekleyen incident artık yalnızca bir
yanıt gelirse oluşturuluyor. Anahtar başına bellek 1 996 bayttan 668 bayta indi (tracemalloc ile ölçüldü);
100 000 sahte kaynakta tepe bellek 519 MB'tan 219 MB'a, 500 000'de 349 MB.

**Fail-open mı, fail-closed mı?** Tablo dolunca yeni flow'u düşürmek yerine en
eski flow'u çıkarıyoruz. Düşürseydik, saldırgan önce tabloyu doldurup sonra
asıl saldırıyı yapabilirdi; saldırının flow'ları hiç görünmezdi. Çıkarmak
gerçek ve uzun bir bağlantıyı ikiye bölebilir; bu daha küçük bir zarar ve
çıktıda sayılarak raporlanıyor.

## 7. Ağır vuruşçular (heavy hitters) ve yaklaşık sayım

"En çok trafik üreten IP'ler" için her IP'ye bir sayaç tutmak, sahte kaynaklı
flood'da sınırsız büyür. `TrafficStats` en fazla `max_endpoints` IP tutar;
dolunca bayta göre en ağır yarısını bırakır ve sonucu `approximate` olarak
işaretler. Ağır vuruşçular bu budamadan sağ çıkar (asıl önemli olan onlar),
kuyruktaki tek paketlik IP'ler düşer. Bu, Space-Saving / Misra-Gries
algoritmalarının basit, toplu (batched) bir akrabasıdır. Bedeli: budanmış bir
IP sonradan geri gelirse sayacı sıfırdan başlar, yani sayımlar alt sınırdır.

## 8. Dürüst ölçüm

Değişikliklerden sonra iki şeyi ölçtük:

1. **Tespit sonuçları değişti mi?** Tüm lab senaryoları `main` dalıyla
   karşılaştırıldı. Tek fark bilinçli bir düzeltme: bir incident kapandıktan
   sonra olayları pencerede kalıyordu ve bir sonraki incident bu, zaten
   raporlanmış olayları yeniden kullanıyordu (`monitoring_poller`'da üst üste
   binen 61,5 saniyelik alarmlar). Artık her olay en fazla bir incident'a ait.
2. **Performans geriledi mi?** Flow takibi ilk haliyle %28 yavaşlattı
   (eşik %20). Profil çıkarınca sürenin ~%60'ının dpkt nesne oluşturmada
   geçtiği görüldü. `struct` tabanlı hızlı yol (ADR-0005) ile referans
   benchmark 3,4–3,9 sn'den ~2,2 sn'ye indi, flow takibi dahil.

## 9. Kontrol soruları ve deneyler

1. `netguard flows` çıktısında bir `nmap -sS` taramasında hangi durumları
   beklersin? `nmap -sT` (connect scan) için ne değişir, neden?
   *(İpucu: connect scan açık portta el sıkışmayı tamamlar.)*
2. Bir SYN flood (`hping3 -S --flood`, yalnızca lab'de) hangi durumda
   flow'lar üretir? Kaynaklar sahteyse ve sunucu SYN-ACK gönderiyorsa
   flow durumu `S0` mı olur, başka bir şey mi? Neden?
3. `seq_after(5, 2**32 - 3)` neden `True`? Kâğıt üzerinde hesapla.
4. Zaman aşımı sınıfları yerine tek bir min-heap (son görülme zamanına göre)
   kullansaydık her paket için maliyet ne olurdu? Neden bu yaklaşımda heap'i
   güncellemek pahalı?
5. **Deney:** `benchmarks/flood_memory.py`'yi `max_flows` değerini
   değiştirerek (`Engine(Config(flows=FlowConfig(max_flows=...)))`) çalıştır.
   Bellek ve `evicted` sayısı nasıl değişiyor? 4 GB'lık Ubuntu sunucu için
   hangi değeri seçerdin?
6. **Deney (lab):** Bir lab yakalamasını hem `netguard flows` hem de Zeek
   (`zeek -r capture.pcap`, `conn.log`) ile işle. Durum dağılımlarını
   karşılaştır. Farklar nereden geliyor?
