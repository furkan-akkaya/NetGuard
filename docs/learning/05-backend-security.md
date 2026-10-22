# Öğrenme notu 05 — Düşmanca dosyaları kabul eden bir backend nasıl güvenli tasarlanır?

> Faz 4 · İlgili kod: `store.py`, `jobs.py`, `worker.py`, `web/app.py`, `web/settings.py`
> İlgili karar: [ADR-0008](../adr/0008-backend-storage-and-api.md) · Referans: [API.md](../API.md)

## 1. Tehdit modeli: ne koruyoruz, kimden?

Backend'in işi, kullanıcının yüklediği pcap dosyalarını analiz etmek. Bu
dosyalar **saldırgan kontrollü**: içlerindeki her bayt, ağdaki biri tarafından
üretilmiş olabilir. Ayrıca API'ye ağdan erişilebiliyorsa istekler de
düşmanca olabilir. Varlıklarımız:

| Varlık | Tehdit | Önlem |
|---|---|---|
| API sürecinin çalışmaya devam etmesi | parser hatası, sonsuz döngü, bellek patlaması | analiz ayrı süreçte, zaman/CPU/bellek sınırlı |
| Disk | dev yükleme, aynı dosyanın tekrar tekrar yüklenmesi | akış sırasında boyut sınırı, SHA-256 ile tekilleştirme |
| Veritabanı | SQL injection | yalnızca parametreli sorgular, sıralama için allowlist |
| Dosya sistemi | path traversal (`../../etc/passwd`) | dosya adı yalnızca etiket, saklanan ad rastgele id |
| Yakalama içeriği (gizli veri) | yetkisiz okuma | varsayılan `127.0.0.1`, token, `0700`/`0600` izinler |

## 2. Süreç izolasyonu: neden thread değil de ayrı süreç?

Analizi API sürecinin bir thread'inde çalıştırsaydık, decoder'daki tek bir
hata (ya da `caplen = 0xFFFFFFFF` gibi bir bellek bombası) **tüm servisi**
düşürürdü. Ayrı süreçte:

- çökme yalnızca o işi bitirir (`failed`), API çalışmaya devam eder;
- `RLIMIT_AS` ile bellek, `RLIMIT_CPU` ile CPU süresi işletim sistemi
  tarafından sınırlanır (Linux; macOS `RLIMIT_AS`'ı uygulamaz, belgelendi);
- süre aşılınca tüm **süreç grubu** `SIGKILL` ile öldürülür
  (`start_new_session=True` sayesinde).

Sınırları `preexec_fn` ile değil worker'ın kendi başlangıcında koyuyoruz:
Python belgeleri, thread'li bir süreçte `preexec_fn` kullanmanın kilitlenmeye
yol açabileceğini söyler. Küçük ama gerçek bir detay.

**Durum makinesi:** `queued → running → done | failed | cancelled`. Her geçiş
tek bir SQL işleminde ve koşullu yapılır: `UPDATE ... WHERE status =
'running'`. Böylece iptal edilmiş bir işin sonucunu geç kalan bir worker
"geri getiremez". İşleri sahiplenme `BEGIN IMMEDIATE` ile yapılır: SQLite yazma
kilidini en baştan alır, iki runner aynı işi alamaz.

## 3. Yükleme: neden multipart değil?

Multipart form yüklemelerinde framework genellikle dosyanın tamamını önce
geçici bir dosyaya yazar, sonra kodumuz çalışır. Boyut sınırını o noktada
kontrol etmek için çok geçtir: disk zaten dolmuştur. NetGuard dosyayı **ham
istek gövdesi** olarak alır ve parça parça okurken:

1. boyutu sayar, sınırı aşınca anında 413 döner ve geçici dosyayı siler;
2. SHA-256'yı aynı geçişte hesaplar (dosyayı ikinci kez okumaz);
3. ilk 4 baytın pcap/pcapng sihirli sayısı olduğunu kontrol eder (415).

`Content-Length` başlığı da kontrol edilir, ama ona güvenilmez: başlık yalan
söyleyebilir, asıl sınır akış sırasında sayılan baytlardır.

## 4. SQL injection: parametreler yetmediği yer

`WHERE src = ?` gibi değerleri parametre olarak bağlamak injection'ı önler.
Ama **sütun adları ve `ORDER BY`** parametre olamaz. İstemci `sort=summary;
DROP TABLE alerts` gönderirse ne olur? NetGuard sıralama anahtarını bir
sözlükte arar (`_ALERT_SORTS`) ve SQL'e yalnızca sözlükteki sabit ifadeyi
koyar; bilinmeyen anahtar 400 döner (`test_alert_filters_sorting_and_validation`).
Metin araması `LIKE` ile yapılır, ve kullanıcının `%` ile `_` karakterleri
kaçışlanır: aksi halde `q=%` her şeyi eşleştirirdi.

## 5. Kimlik doğrulama ve güvenli varsayılanlar

- Varsayılan bağlanma adresi `127.0.0.1`: yalnızca aynı makineden erişim.
- `0.0.0.0`'a token olmadan bağlanmak **reddedilir**. "Varsayılan olarak
  güvenli, bilinçli olarak güvensiz" ilkesi: güvensiz ayar için açık bir
  bayrak (`--insecure-no-auth`) gerekir.
- Token karşılaştırması `hmac.compare_digest` ile yapılır. Normal `==`
  karşılaştırması ilk farklı baytta durur ve yanıt süresi tokenin ne kadarının
  doğru olduğunu sızdırabilir (timing side channel).
- Token en az 16 karakter; HTTP düz metindir, uzaktan erişimde önüne TLS
  (reverse proxy) konulmalı. Bu NetGuard'ın değil, dağıtımın işi; SECURITY.md'de
  yazıyor.

## 6. Kontrol soruları ve deneyler

1. `finish_analysis` neden `WHERE status = 'running'` koşulu içeriyor? Bu
   koşul olmasaydı hangi yarış durumu (race condition) oluşurdu?
2. Worker'ın hata mesajında neden dosya yolunu `<capture>` ile
   değiştiriyoruz? İstemciye sunucu yolu sızdırmanın riski ne?
3. SHA-256 ile tekilleştirme bir saldırgana hangi bilgiyi verebilir?
   (İpucu: aynı dosya daha önce yüklenmişse yanıt 201 değil 200.) Tek
   kullanıcılı bir sistemde bu önemli mi, çok kullanıcılıda?
4. **Deney:** `netguard serve --max-upload-mb 5` çalıştır ve bitmeyen bir akış
   yükle: `( printf '\xd4\xc3\xb2\xa1'; cat /dev/zero ) | curl -X POST -T -
   -H 'Content-Type: application/octet-stream' "$B/captures"`. (Dikkat:
   `--data-binary @/dev/zero` işe yaramaz, curl dosyayı önce belleğe okumaya
   çalışır.) Sunucu hangi kodla ve kaç bayttan sonra kesiyor? `captures/`
   klasöründe bir şey kalıyor mu? curl'ün gönderdiği bayt sayısı neden sınırdan
   biraz fazla?
5. **Deney (Ubuntu):** `--job-memory-mb 64` ile büyük bir pcap analiz et.
   İş hangi hata ile bitiyor? Aynısını macOS'ta dene, fark ne ve neden?
