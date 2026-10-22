# Öğrenme notu 04 — DNS kötüye kullanımı, kişisel baseline'lar ve parçalama ile atlatma

> Faz 3 · İlgili kod: `dns.py`, `detectors/dnstunnel.py`, `detectors/nxdomain.py`,
> `baseline.py`, `detectors/connrate.py`, `detectors/volume.py`, `detectors/fragments.py`
> İlgili karar: [ADR-0007](../adr/0007-per-host-baselines.md)

## 1. DNS neden saldırganın sevdiği bir protokol?

Neredeyse her ağ DNS'e izin verir ve çoğu kurum içeriğine bakmaz. Bir
saldırgan iki şekilde kullanır:

- **Tünelleme / sızdırma:** veriyi sorgu adına kodlar:
  `6b3f...a91c.t.saldirgan.example`. Saldırganın yetkili DNS sunucusu adı
  çözer, yanıtı (genellikle TXT kaydı) komut olarak geri yollar. iodine,
  dnscat2 ve Cobalt Strike'ın DNS beacon'ı böyle çalışır.
- **DGA:** zararlı yazılım her gün yüzlerce alan adı üretir ve hangisinin
  kayıtlı olduğunu bulana kadar dener. Engellemeyi zorlaştırır, ama
  denemelerin neredeyse hepsi **NXDOMAIN** (böyle bir alan adı yok) döner.

### Kendi DNS ayrıştırıcımız

`dns.py` yalnızca başlığı ve ilk soruyu okur. Daha önce dpkt bozuk UTF-8 içeren
bir adda hata fırlatıyor ve tüm paket görünmez oluyordu (not 02). Şimdi ASCII
olmayan baytlar `\xc6` gibi görünür bir kaçış dizisine dönüşüyor. Bu tünelleme
tespiti için bir kanıttır, saklanması gereken bir hata değil. Sıkıştırma
işaretçileri (compression pointer) bir atlama sınırıyla izleniyor, böylece
kendine işaret eden bir ad ayrıştırıcıyı sonsuz döngüye sokamıyor.

## 2. Entropi: "rastgele görünme"nin ölçüsü

Shannon entropisi, karakter başına ortalama bilgi miktarıdır:

```text
H = -Σ p(c) · log2 p(c)
```

| Metin | H (bit/karakter) |
|---|---:|
| `aaaa` | 0 |
| `google` | ~1,9 |
| `abcd` | 2,0 |
| 64 karakterlik hex | 4,0 (hex'in üst sınırı: log2 16) |

**Tuzak:** kısa metinlerde entropi düşük çıkar. 5 karakterlik bir metin en
fazla log2(5) ≈ 2,3 bit/karakter olabilir. Bu yüzden NG-DNS-001 karar için
*uzunluk ve benzersiz alt alan adı sayısını* kullanır; entropi yalnızca
kanıt olarak raporlanır. Tek başına bir entropi eşiği CDN adlarında
(`e1234.akamaiedge.net`) yanlış pozitif, kısa kodlamalarda yanlış negatif
üretirdi. `cdn_lookups` senaryosu tam bunu test eder.

### NXDOMAIN: sayı yetmez, dağılıma bak

Bir dizüstünün DNS arama son eki (search suffix) yanlışsa her kısa ad önce
`ad.corp.example` olarak denenir ve başarısız olur. Sayı olarak DGA'dan
ayırt edilemez (`search_suffix_nxdomain` senaryosu, **ölçülmüş bir yanlış
pozitif**). Kanıt farkı gösterir: arama son eki sorununda adlar bir alan adında
toplanır ve okunabilirdir, DGA'da her ad farklı bir alan adıdır. Alarm bunu
özet metninde söyler, analist karar verir.

## 3. Kişisel baseline: "bu host için normal mi?"

Dakikada 2 000 yeni bağlantı bir proxy için normal, bir dizüstü için
alarmdır. Tek bir global eşik ya gürültülü ya da kör olur. `baseline.py` her
host için iki sayı tutar:

```text
sapma    = (1 - α) · sapma + α · |x - ortalama|
ortalama = ortalama + α · (x - ortalama)          (α = 0,1 ≈ son 10 aralık)
```

Bu bir **EWMA** (üstel ağırlıklı hareketli ortalama). Host başına O(1) bellek:
geçmiş değerleri saklamıyoruz. Varyans yerine mutlak sapmayı kullanıyoruz,
çünkü varyans kareler aldığı için tam da aradığımız sıçramalardan en çok
etkilenen istatistiktir.

**Üç ince nokta:**

1. **Taban (floor):** tamamen düzenli bir hostta sapma 0'a iner ve her küçük
   artış alarm üretir. Eşik `ortalama + 6 · max(sapma, 0,25 · ortalama, 1)`.
2. **Kırpma (clipping):** saldırı aralığı baseline'a tam değeriyle eklenseydi
   saldırı hızla "normal" olurdu (baseline zehirlenmesi). Eşiğe kırpılarak
   ekleniyor. Kalıcı bir değişiklik ise birkaç aralıkta öğreniliyor.
3. **Isınma (warm-up):** ilk 10 aralıkta (10 dakika) karar verilmez. Kısa
   pcap'lerde bu kurallar hiçbir zaman alarm üretmez. Bu bir sınırlama ve
   belgelendi.

`growing_workload` senaryosu (her dakika %10 artış) neden alarm üretmiyor?
EWMA artışı takip ediyor ve sapma da büyüyor. Yavaş yavaş artan bir saldırı da
aynı şekilde görünmez kalır; bu da baseline yaklaşımının bilinen bedeli.

## 4. Parçalama ile atlatma (RFC 1858)

Bir IP paketi yol üzerindeki MTU'dan büyükse parçalara bölünür. Saldırgan bunu
bilerek kullanabilir: `nmap -f` her probe'u **8 baytlık** parçalara böler.
Böylece ilk parçada TCP başlığının yalnızca ilk 8 baytı (portlar ve sıra
numarası) bulunur; bayraklar sonraki parçadadır. Paketleri tek tek inceleyen bir
filtre veya IDS "SYN"i göremez.

NetGuard parça birleştirme (reassembly) yapmıyor. Bu bilinçli bir karar:
birleştirme bellek gerektirir, kendisi de bir saldırı yüzeyidir (Teardrop,
örtüşen parçalar) ve doğru yapmak zordur. Bunun yerine NG-FRAG-001 **atlatma
girişiminin kendisini** görünür kılar:

- TCP başlığını taşıyamayacak kadar küçük ilk parça,
- offset 8'de başlayan TCP parçası (başlık bölünmüş ya da üzerine yazılıyor),
- MTU'dan çok küçük, son olmayan parçalar (gerçek parçalama ≥ 576 baytta olur).

`fragmented_udp` senaryosu (1 500 MTU'da normal parçalama) sessiz kalıyor.

## 5. Kontrol soruları ve deneyler

1. `shannon_entropy("abab")` ve `shannon_entropy("abcd")` kaçtır? Neden ikincisi
   daha yüksek?
2. Bir DNS tüneli NG-DNS-001'den kaçmak için ne yapabilir? (Kısa label'lar,
   yavaş hız, çok sayıda alan adına dağılma.) Her birinin saldırgana bedeli
   nedir (bant genişliği, altyapı)?
3. NXDOMAIN kuralını DNS sunucusunun yanıtları yerine istemcinin sorgularına
   göre yazsaydık ne kaybederdik?
4. α = 0,5 olsaydı baseline nasıl davranırdı? `connection_burst` senaryosu
   hâlâ tespit edilir miydi? Tahmin et, sonra
   `Config(connrate=ConnRateConfig(smoothing=0.5))` ile dene.
5. Neden baseline'a anomali değerini değil eşiği ekliyoruz? Saldırgan bunu
   nasıl istismar edebilir?
6. **Deney (lab):** Kali'den `nmap -f -sS -p 1-100 <ubuntu>` çalıştır. NG-SCAN-001
   ve NG-SCAN-002 bir şey görüyor mu? NG-FRAG-001 hangi türleri raporluyor?
   Aynı taramayı `--mtu 24` ile tekrarla: ne değişti?
7. **Deney (lab, yalnızca izole ağ):** `iodine` veya `dnscat2` ile kısa bir
   tünel kurup birkaç dosya aktar. `mean_subdomain_length` ve
   `query_types` ne çıkıyor?
