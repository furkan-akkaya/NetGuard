# Öğrenme notu 03 — Bağlantı sonucuna bakmak: TRW ve ardışık hipotez testi

> Faz 3 · İlgili kod: `detectors/trw.py`, `detectors/synflood.py`, `flows.py` (bağlantı olayları)
> İlgili kararlar: [ADR-0006](../adr/0006-connection-events-and-outcome-aware-scans.md) · Kural: [NG-SCAN-002](../rules/NG-SCAN-002.md)

## 1. Problem: pencere tabanlı tespitin iki zayıflığı

Not 01'deki pencere dedektörü "60 saniyede 15 farklı port" sayıyordu. İki sorunu vardı:

1. **Sonuca bakmıyor.** Pasif FTP istemcisi 25 farklı porta bağlanır ve hepsi
   başarılı olur; dedektör bunu tarama sanıyordu.
2. **Zamana bağlı.** 15 saniyede bir probe gönderen bir tarayıcı, 60 saniyelik
   pencereye hiçbir zaman 15 port sığdırmaz ve görünmez kalır.

Asıl soru şu: *bu kaynak, var olmayan servislere mi bağlanmaya çalışıyor?*
Meşru bir host çoğunlukla var olan servislere bağlanır (bağlantılarının çoğu
başarılı olur). Tarayıcı ise neyin var olduğunu bilmez; çoğu denemesi
başarısız olur.

## 2. Fikir: her ilk temas bir yazı-tura

Jung vd. (2004) her kaynağın *ilk temas* bağlantı denemelerini (daha önce
denemediği bir hedefe) bir Bernoulli denemesi olarak modeller:

- H₀ (benign): başarı olasılığı θ₀ = 0,8
- H₁ (tarayıcı): başarı olasılığı θ₁ = 0,2

Her sonuçtan sonra iki hipotezin olabilirlik oranını güncelleriz. Çarpımlar
yerine logaritmaları topluyoruz (sayısal olarak kararlı ve toplama O(1)):

```text
başarı:    Λ += ln(θ₁/θ₀)         = ln(0,25) ≈ -1,39   (benign'e doğru)
başarısız: Λ += ln((1-θ₁)/(1-θ₀)) = ln(4)    ≈ +1,39   (tarayıcıya doğru)
```

Buna **rastgele yürüyüş** denmesinin nedeni bu: Λ her adımda yukarı ya da
aşağı gider.

## 3. Ne zaman karar veririz? Wald'ın SPRT'si

Wald'ın ardışık olasılık oranı testi (SPRT), istenen tespit (P_D) ve yanlış
pozitif (P_F) olasılıklarından iki eşik çıkarır:

```text
Λ ≥ ln(P_D / P_F)             = ln(0,99/0,01) ≈ 4,60   → tarayıcı
Λ ≤ ln((1-P_D) / (1-P_F))     ≈ -4,60                  → benign (yürüyüşü sıfırla)
```

Varsayılanlarla her başarısızlık +1,39 eklediği için arka arkaya **4
başarısızlık** (5,55 ≥ 4,60) "tarayıcı" kararı için yeter. SPRT'nin güzel
yanı, sabit örneklem boyutlu bir teste göre **ortalamada en az gözlemle**
karar vermesidir. Tarayıcı birkaç probe'da yakalanır, benign hostlar için
ise gereksiz bekleme olmaz.

**Pratik ek:** gerçek ağlarda bir istemcinin art arda dört ölü servisi denemesi
nadir değildir (eski bir yazıcı adresi, kapanmış bir sunucu). Bu yüzden
NetGuard ayrıca `min_failures = 5` ister. Bu, makaledeki modele bilerek
eklenmiş, belgelenmiş bir sapma.

## 4. Sonucu kim söylüyor? Bağlantı olayları

TRW'nin her deneme için "başarılı mı?" bilgisine ihtiyacı var. Bunu flow
tablosu veriyor (ADR-0006):

| Olay | Paket | TRW için anlamı |
|---|---|---|
| `attempt` | başlatanın SYN'i yeni flow açtı | ilk temas mı? kaydet |
| `answered` | yanıtlayanın ilk SYN-ACK'i | başarı |
| `rejected` | SYN-ACK'ten önce RST | başarısızlık (kapalı port) |
| flow sonu, durum `S0`, `end_reason="idle"` | 30 sn yanıt yok | başarısızlık (filtreli/yok) |
| flow sonu, `eof` veya `evicted` | yakalama bitti / tablo doldu | **bilinmiyor**, sayılmaz |

Son satır önemli: yakalama bir el sıkışmanın ortasında bittiyse bu bir
başarısızlık değildir. Bunu ayırt etmeseydik her kısa pcap'in sonunda sahte
"yanıtsız" sonuçlar üretirdik.

## 5. Ölçülen sonuç

| Senaryo | v0.2 (yalnızca pencere) | v0.3 |
|---|---|---|
| `passive_ftp` | yanlış pozitif | sessiz (26 başarı, Λ aşağı gidiyor) |
| `slow_scan` (15 sn'de bir probe) | kaçırıldı | 6 sonuçtan sonra TRW yakaladı |
| `syn_scan_1000` | tespit | iki kural da tespit etti |

**Bedel:** TRW'nin penceresi yok ama belleği var. Kaynak başına ~0,3 KB durum
tutuluyor ve `state_timeout_seconds` (1 saat) yavaş tarama ufkunu belirliyor.
Saatte bir probe gönderen tarayıcı yine kaçar. Her tespit yönteminin bir
"altında kalınabilir" eşiği vardır; önemli olan bunu bilmek ve belgelemek.

## 6. Aynı fikir, başka bir kural: SYN flood

SYN flood da bir *sonuç* problemidir. Çok sayıda SYN alan bir sunucu popüler
olabilir. Saldırı altında olduğunu gösteren, **el sıkışmaların
tamamlanmamasıdır**. NG-SYN-001 her `ip:port` hedefi için 10 saniyelik
aralıklarda `attempt` ve `established` olaylarını sayar ve
`established / attempt ≤ 0,2` ise aralığı şüpheli işaretler. `flash_crowd`
senaryosunda 800 istemci 4 saniyede bağlanır ama hepsi el sıkışmayı tamamlar,
bu yüzden alarm yok. `syn_flood_spoofed`'da 6 000 SYN'in hiçbiri tamamlanmaz.

## 7. Kontrol soruları ve deneyler

1. θ₀ = 0,9 ve θ₁ = 0,1 olsaydı kaç ardışık başarısızlık karar için
   yeterdi? Kâğıt üzerinde hesapla, sonra `TrwDetector(Config(trw=TrwConfig(...)))`
   ile `step_failure` ve `upper` değerlerini kontrol et.
2. Başarı ve başarısızlıkların sırayla geldiği (%50 başarı) bir kaynak neden
   hiçbir zaman "tarayıcı" olmuyor? Λ'nın beklenen adım değerini hesapla.
3. `nmap -sX` (XMAS) taraması TRW'de neden görünmez? Hangi kural onu yakalar?
4. Bir saldırgan TRW'yi atlatmak için ne yapabilir? (İpucu: başarı oranını
   yükseltmek için bilinen açık portlara bağlantıları araya karıştırmak.)
   Bu atlatmanın saldırgana maliyeti ne?
5. **Deney (lab):** Kali'den `nmap -sS -T1 -p 1-50 <ubuntu>` çalıştır.
   NG-SCAN-001 ve NG-SCAN-002 sonuçlarını karşılaştır. TRW kaç sonuçtan sonra
   karar verdi (`decided_after_outcomes`)?
6. **Deney (lab):** Ubuntu'da SYN cookies açıkken (`net.ipv4.tcp_syncookies=1`)
   `hping3 -S --flood --rand-source -p 80 <ubuntu>` (yalnızca izole lab'de,
   birkaç saniye). `answer_ratio` nasıl çıkıyor ve neden?
