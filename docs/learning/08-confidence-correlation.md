# Öğrenme notu 08 — Alarmdan karara: güven puanı, korelasyon ve bağlam

> Faz 7 · İlgili kod: `confidence.py`, `correlate.py`, `dhcp.py`, `detectors/arpspoof.py`
> İlgili karar: [ADR-0011](../adr/0011-phase-7-feature-selection.md) · Ayrıntı: [CONFIDENCE.md](../CONFIDENCE.md)

## 1. Bir özelliği neden eklemiyoruz?

Brief, Faz 7 için uzun bir aday listesi veriyordu: baseline, anomali tespiti,
korelasyon, güven puanı, Zeek/Suricata girdisi, ML… Hepsini yapmak kolaydı ve
portföyde etkileyici görünürdü. Kural şuydu: **ölçülebilir değer göstermeyen
özellik eklenmez.** Önce mevcut durumu ölçtük:

- 3 yanlış pozitifin hiçbiri alarm sayısı ya da şiddetiyle gerçek saldırılardan
  ayırt edilemiyordu.
- Bir SYN taraması 2, bir ARP MITM saldırısı 4 alarm üretiyordu.

Bu iki gözlem iki özelliği gerektirdi (güven ve korelasyon), üçüncüsü
(DHCP) bir yanlış pozitifin somut nedenini hedefledi. ML ise reddedildi.
Etiketli gerçek veri yok, açıklanabilir değil, ölçecek bir şey de yok. "ML
kullandım" demek değer değildir.

## 2. Açıklanabilir güven puanı

İki alarm aynı kuraldan gelebilir ama biri çok daha inandırıcıdır. NXDOMAIN
patlaması örneği:

| | DGA | Yanlış arama son eki |
|---|---|---|
| 60 ad, 59 farklı alan adı | ✓ | |
| 30 ad, tek alan adı (`*.corp.example`) | | ✓ |
| Rastgele görünen etiketler | ✓ | |

Model bilinçli olarak basit: **taban + faktör ağırlıkları**, 5–95 arasına
sıkıştırılmış.

```text
NG-DNS-002 taban 50
  +25  adların neredeyse hepsi farklı alan adı (DGA böyle üretir)
  +10  rastgele görünen etiketler
  −25  hatalar 1–2 alan adında toplanıyor (yanlış arama son eki)
```

Neden lojistik regresyon ya da bir sınıflandırıcı değil?

1. **Açıklanabilirlik:** analist her puanın *neden* öyle olduğunu tek satırlık
   gerekçelerle görür (dashboard'da da gösteriliyor).
2. **Veri yok:** öğrenilmiş ağırlıklar etiketli gerçek veri ister. Elimizde
   yalnızca kendi tasarladığımız senaryolar var.
3. **Hiçbir zaman 0 ya da 100 değil:** ağ kanıtı niyeti kanıtlamaz.

**Dürüstlük notu:** Ölçümde tüm yanlış pozitifler 25–30, tüm doğru
pozitifler 45–95 aldı. Ama kuralları, faktörleri ve senaryoları aynı kişi
yazdı. Faktörleri senaryolara bakarak seçmek kolayca **aşırı uyuma
(overfitting)** dönüşür. Korunma yöntemimiz: her faktör protokol bilgisiyle
gerekçelendirilir (CONFIDENCE.md'deki "Neden" sütunu), puanlara göre
ayarlanmaz, ve Faz 8'de gerçek yakalamalarda ayırt etmeyen faktör çıkarılır.
Sonuç "doğruluk" değil, **tutarlılık kontrolü** olarak raporlanıyor.

## 3. Korelasyon: alarmdan olaya

Analist 4 ayrı alarm değil, "10.0.0.20 bir C2 tüneli kurdu, sonra iç sunucuyu
taradı ve parçalanmış paketlerle atlatmaya çalıştı" hikâyesini görmek ister.

Algoritma: alarmlar **aktöre** göre gruplanır (kaynak; kaynağı olmayan SYN
flood gibi alarmlarda hedef) ve zaman aralıkları en fazla 15 dakika arayla
ise aynı olaya katılır. Gruplama geçişlidir (A~B, B~C ⇒ A, B, C aynı olay).
Sıralama + aktör başına tek geçiş: **O(n log n)**. Teknikler ATT&CK
taktiklerine eşlenir ve kill-chain sırasıyla gösterilir:
`Defense Evasion → Discovery → Command and Control`.

Sınırlama: ARP alarmlarında aktör MAC adresi, tarama alarmlarında IP adresi.
Aynı saldırgan iki olay olarak görünebilir. IP↔MAC eşlemesiyle birleştirmek
sonraki bir adım.

## 4. Bağlam: DHCP ve "ilk kullanımda güven"

Bir IP'nin MAC'i değişti. Saldırı mı, yeni bir dizüstü mü? Tek başına ARP bunu
söyleyemez, ama DHCP söyleyebilir: sunucu az önce bu IP'yi bu MAC'e verdiyse
bu bir yeniden atamadır.

Burada saldırgan ne yapar? **Sahte bir DHCP ACK** gönderir ("ağ geçidi IP'si
benim MAC'imde") ve sonra ARP zehirler. Bu yüzden yalnızca **güvenilen**
sunucunun ACK'leri bir değişikliği açıklayabilir: ya yapılandırılmış liste
(`dhcp_servers`) ya da ilk görülen sunucu (*trust on first use*, SSH'ın
`known_hosts` mantığı). `arp_spoof_with_rogue_dhcp` senaryosu tam bu saldırıyı
dener ve tespit edilir. TOFU'nun zayıflığı da açık: sahte sunucu gerçeğinden
**önce** cevap verirse güvenilir olan o olur. Bu yüzden belgelerde
`dhcp_servers`'ı açıkça ayarlamak öneriliyor.

## 5. Kontrol soruları ve deneyler

1. Güven modeline yeni bir faktör eklemek istiyorsun. Onu nasıl
   gerekçelendirirsin ve hangi veriyle doğrularsın? Senaryolara bakarak
   ağırlık seçmek neden tehlikeli?
2. Korelasyon aralığını 15 dakikadan 24 saate çıkarsaydık ne kazanır, ne
   kaybederdik? (İpucu: NAT arkasındaki bir IP.)
3. Bir saldırgan güven puanını düşürmek için ne yapabilir? Örneğin tarama
   portlarının yarısını açık olduğunu bildiği portlardan seçmek. Bu atlatmanın
   ona maliyeti ne?
4. DHCP'nin yanında hangi bağlam bilgileri ARP yanlış pozitiflerini
   azaltabilirdi? (VRRP/HSRP sanal MAC adresleri, 802.1X oturumları…)
5. **Deney:** `netguard config > mine.toml` ile tam yapılandırmayı al, bir
   eşiği değiştir, dashboard'da *Rules → Import TOML* ile profil olarak içe
   aktar ve aynı yakalamayı iki profille analiz et. Alarmların güven puanları
   nasıl değişti?
6. **Deney (lab):** Lab ağında bir DHCP sunucusu (ör. Ubuntu'da `dnsmasq`)
   çalışırken yeni bir VM'yi ağa bağla ve bir VM'nin IP'sini başka bir VM'ye
   ver. NetGuard ne raporluyor? Ardından Kali'den `bettercap`'in `arp.spoof`
   modülünü (yalnızca izole lab'de) dene. Not: NetGuard yalnızca DHCPv4'ü
   okuyor; DHCPv6 ve IPv6 komşu keşfi (NDP) saldırıları kapsam dışında.
