# Portfolio material (draft)

Drafts for LinkedIn, a CV and interviews. Every claim maps to a measurement
or a file in this repository; the source is noted after each fact list.
Update the numbers when Phase 8 (real lab captures) is done, and do not add
claims that have no measurement behind them.

Rules for editing this text:

- Say "synthetic lab scenarios" whenever precision/recall is mentioned.
- Do not call NetGuard production-ready or compare it with Zeek/Suricata as
  an equal; it is a focused analysis tool for small networks.
- If AI assistance was used in development, say so plainly; it is better
  to be asked about it than to be found out.

## LinkedIn post (English)

> I built **NetGuard**, a network intrusion detection and traffic analysis
> tool, as my cybersecurity engineering portfolio project.
>
> It reads pcap/pcapng files or a live tcpdump stream, rebuilds TCP/UDP
> flows with Zeek-style connection states, and runs 11 explainable detection
> rules: port scans (including a sequential hypothesis test for slow scans),
> host sweeps, SYN floods, ARP spoofing with DHCP lease correlation, DNS
> tunnelling, DGA-like lookup bursts, fragmentation evasion and per-host
> traffic baselines. Every alert explains itself: the evidence, the
> thresholds it crossed, a confidence score with the factors behind it, and
> the MITRE ATT&CK technique. Alerts about the same host are grouped into
> incidents. There is a CLI, an HTML report, a REST API and a React
> dashboard.
>
> What I learned most from was measuring and attacking my own code:
> - A library's capture reader trusted a length field: one crafted record
>   made a 300 MB stream use 628 MB of memory. I wrote bounded readers.
> - A spoofed-source flood made detector cleanup O(n) per packet; with O(1)
>   eviction 500k flood packets now stay at ~470 MB.
> - Attacking the localhost API from a browser worked (DNS rebinding,
>   cross-site uploads) until I added Host and Origin checks.
>
> Results so far, on 27 synthetic lab scenarios (15 attacks, 12 benign
> look-alikes designed to fool the rules): every attack scenario detected,
> 3 known false positives that are published, not tuned away. ~98k
> packets/s offline on an M1. 325 tests, 93% coverage, CI on Linux and
> macOS. Next step: validating it on real traffic in an isolated lab.
>
> [link to repository] #cybersecurity #networksecurity #IDS #python

Sources: README, EVALUATION.md §2–3, ADR-0005, THREAT_MODEL.md.

## LinkedIn gönderisi (Türkçe)

> Siber güvenlik mühendisliği portföy projem olarak **NetGuard**'ı geliştirdim:
> bir ağ saldırı tespit ve trafik analiz aracı.
>
> pcap/pcapng dosyalarını ya da canlı bir tcpdump akışını okuyor, TCP/UDP
> bağlantılarını Zeek tarzı durumlarla yeniden kuruyor ve 11 açıklanabilir
> tespit kuralı çalıştırıyor: port taramaları (yavaş taramalar için ardışık
> hipotez testi dahil), host taramaları, SYN flood, DHCP kira korelasyonlu
> ARP spoofing, DNS tünelleme, DGA benzeri sorgu patlamaları, fragmentasyonla
> atlatma ve host bazlı trafik baseline'ları. Her alarm kendini açıklıyor:
> kanıt, aşılan eşikler, arkasındaki faktörlerle bir güven skoru ve MITRE
> ATT&CK tekniği. Aynı host'a ait alarmlar olaylarda birleşiyor. CLI, HTML
> rapor, REST API ve React dashboard var.
>
> En çok kendi kodumu ölçüp ona saldırarak öğrendim:
> - Bir kütüphanenin okuyucusu bir uzunluk alanına güveniyordu: tek bir
>   hazırlanmış kayıt, 300 MB'lık akışta 628 MB bellek kullandırdı. Sınırlı
>   okuyucular yazdım.
> - Sahte kaynaklı bir flood, dedektör temizliğini paket başına O(n) yapıyordu;
>   O(1) tahliye ile 500 bin flood paketi ~470 MB'ta kalıyor.
> - Localhost API'ye tarayıcıdan saldırmak işe yaradı (DNS rebinding,
>   cross-site yükleme); Host ve Origin kontrollerini ekleyene kadar.
>
> Şimdiye kadarki sonuçlar, 27 sentetik lab senaryosunda (15 saldırı, kuralları
> yanıltmak için tasarlanmış 12 benign benzeri): her saldırı senaryosu tespit
> edildi, bilinen 3 false positive gizlenmeden yayımlandı. M1'de offline
> ~98 bin paket/s. 325 test, %93 kapsama, Linux ve macOS'ta CI. Sıradaki adım:
> izole bir lab'de gerçek trafikle doğrulama.

## CV bullets

- Built NetGuard, a network intrusion detection tool in Python (≈8.8k lines)
  with a FastAPI backend and React/TypeScript dashboard: 11 explainable
  detection rules, flow reconstruction, alert correlation with MITRE ATT&CK.
- Designed a reproducible evaluation with 27 labelled synthetic scenarios
  including benign look-alikes; all 15 attack scenarios detected, 3 known
  false positives documented.
- Wrote a threat model and fixed the 7 findings of the review, found partly
  by attacking my own service (DNS rebinding, cross-site writes, resource
  exhaustion); bounded all detector state against spoofed-source floods.
- Set up CI/CD with GitHub Actions: strict typing, 325 tests across 2 OS ×
  4 Python versions, dependency audit, license gate, SBOM in releases.

## Interview talking points

| Question | Short answer | Where to show it |
|---|---|---|
| Why not just use Zeek/Suricata? | NetGuard is for learning and small networks; it borrows Zeek's connection states on purpose and does not compete on scope | ARCHITECTURE.md, ADR-0004 |
| How do you know the rules work? | Labelled scenarios with benign look-alikes, pinned in CI; real-traffic validation is the open next step | EVALUATION.md §1–2 |
| How does slow-scan detection work? | Threshold Random Walk: a sequential likelihood-ratio test on connection outcomes, no time window | NG-SCAN-002, ADR-0006 |
| What happens under a flood? | Memory stays bounded with O(1) eviction; detection degrades and the output says so | EVALUATION.md §3, learning note 02 |
| What was the hardest bug? | Pick one from ENGINEERING_REPORT.md §4 and explain how it was found | ENGINEERING_REPORT.md |
| What would you do next? | Real lab captures, Zeek comparison, then decide on reassembly and baselines based on that data | RELEASE_CHECKLIST.md |
