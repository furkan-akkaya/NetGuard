# Öğrenme notu 10 — Release ve dürüst değerlendirme

> Faz 10 · İlgili doküman: [ENGINEERING_REPORT.md](../ENGINEERING_REPORT.md),
> [RELEASE_CHECKLIST.md](../RELEASE_CHECKLIST.md), [DEMO.md](../DEMO.md)

## 1. "Sayılıyor" ile "gösteriliyor" aynı şey değil

Tehdit modelinde "tablo dolunca durum düşürülür ve bu sayılır" yazıyordu.
Kod gerçekten sayıyordu: `self.evicted_sources += 1`. Ama bu sayaçları hiçbir
çıktı okumuyordu. Analist, sahte kaynaklı bir flood sırasında portscan ve TRW
tablolarının 400 binden fazla kaydı attığını göremiyordu. Yani flood içine
saklanmış gerçek bir taramanın kaçmış olabileceğini bilemiyordu.

Bulma yolu sıkıcıydı ama işe yaradı: `vulture` ile "atanıp hiç okunmayan"
alanları listeledim, sonra her birinin bir hata mı yoksa ölü kod mu olduğuna
baktım. Düzeltme küçük: her dedektör sayaçlarını `counters` ile ilan ediyor,
motor bunları analiz istatistiklerine koyuyor, CLI/rapor/dashboard da
`evicted_*` / `untracked_*` sıfırdan büyükse uyarı gösteriyor.

Ders: bir güvenlik kontrolünün (burada: fail-open'ın görünür olması) çıktıda
gerçekten göründüğünü bir testle sabitle (`test_detector_state_losses_are_reported`).

## 2. Grafikler de yalan söyleyebilir

Ekran görüntüsü alırken trafik grafiğinde 08:54:07 ile 08:54:20 arasında
yavaşça yükselen bir rampa vardı. Gerçekte o aralıkta **hiç** trafik yoktu.
API yalnızca dolu zaman dilimlerini gönderiyor, grafik de iki dolu nokta
arasını düz bir çizgiyle birleştiriyordu. Bir SOC analisti bunu "tarama
yavaşça başladı" diye okuyabilirdi.

Çözüm: basamaklı (step) grafik. Her değer kendi zaman dilimi boyunca sabit
kalıyor, boşlukta çizgi sıfıra iniyor. Bunu da bir testle sabitledim.

Ders: görselleştirme de bir iddiadır. Seyrek veriyi enterpolasyonla
çizmek, olmayan bir ölçüm uydurmaktır.

## 3. Definition of Done: "bitti" demenin şartları

Brief, v1.0 için 12 madde sayıyor ve "karşılanamayan madde varsa tam uyum
iddia etme" diyor. Kontrol listesinde 8 madde karşılandı; 3'ü gerçek lab
trafiği (Faz 8), 1'i GitHub'da gerçek bir release çalıştırması istiyor.
Bu yüzden karar şu: **v1.0.0 henüz etiketlenmez.**

Ara yol bir **release candidate**: `v1.0.0rc1` etiketi. Workflow aynı
adımları çalıştırır (dashboard build, wheel, temiz ortamda smoke test, SBOM),
ama sonucu taslak bir *pre-release* olarak bırakır. Böylece "release
artefaktları doğrulandı" maddesi, v1.0 iddiası olmadan karşılanabilir.

Sürüm numarası bir sözdür: `1.0.0` "belgelenen her şey çalışıyor ve
ölçüldü" demektir. Bunu lab verisi olmadan söylemek, değerlendirme
belgelerindeki diğer her iddiayı zayıflatır.

## 4. Projeyi anlatmak

Portföy metninde ([PORTFOLIO.md](../PORTFOLIO.md)) her cümlenin arkasında bir
ölçüm var. Birkaç kural:

- Precision/recall geçen her yerde "sentetik senaryolar" de. Kuralları ve
  senaryoları aynı kişi yazdı; bu bir doğruluk ölçümü değil, bir
  spesifikasyon testi.
- "Production-ready" deme. "Küçük ağlar için, satır hızında olmayan bir
  analiz aracı" de; sınırı bilen biri daha güvenilir görünür.
- En iyi hikâyeler hatalardan çıkıyor: dpkt'nin `caplen`'e güvenmesi, O(n)
  temizlik, DNS rebinding. Mülakatta "nasıl buldum, nasıl ölçtüm, nasıl
  düzelttim" sırasıyla anlat.
- Geliştirmede yapay zekâ desteği kullandıysan bunu açıkça söyle. Sorulduğunda
  kodun her parçasını açıklayabilmen, kimin yazdığından daha önemli. Bu
  notlar ve sorular tam olarak bunun için var.

## 5. Kontrol soruları ve deneyler

1. Bir sayacın "ölü kod" mu yoksa "görünmeyen bir güvenlik sinyali" mi
   olduğuna nasıl karar verirsin?
2. Seyrek bir zaman serisinde boş dilimleri sunucu tarafında mı (sıfırlarla
   doldurarak), istemci tarafında mı ele almak daha iyi? Bellek ve bant
   genişliği açısından karşılaştır.
3. `v1.0.0rc1` ile `v0.9.0` arasındaki fark ne? Hangisi neyi vaat eder?
4. **Deney:** `uv run python benchmarks/flood_memory.py 100000` çalıştır.
   Hangi dedektörler state düşürüyor, `synflood` neden düşürmüyor?
5. **Deney:** `netguard lab generate lab-pcaps/` ile senaryoları yaz, sonra
   `[trw]` bölümünde `max_sources = 10` olan bir TOML ile
   `netguard analyze -c dar.toml lab-pcaps/syn_flood_spoofed.pcap` çalıştır
   (bende: "detector trw dropped state 5,989 times"). Aynı ayarla
   `compromised_workstation.pcap` neden uyarı vermiyor?
6. Kendi LinkedIn metnini PORTFOLIO.md'deki taslaktan yaz ve her cümlenin
   kaynağını işaretle. Kaynağı olmayan cümleyi çıkar.
