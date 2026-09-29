# ROOTIPV6 NetAudit Toolkit

**Developed by Ali Rıza Saydan**

**ROOTIPV6 Security Labs**

---

Terminal tabanlı bir network audit ve analiz aracı. Port tarama, ping sweep, DNS sorgusu, log analizi, SSH başarısız giriş tespiti ve SNMP bilgi toplama gibi işleri tek menü altında topluyor. GUI yok — bilinçli olarak terminalde çalışıyor.


> **Uyarı:** Yalnızca izinli sistemlerde ve meşru audit/test amacıyla kullanın. İzinsiz tarama yasadışıdır.

---

## Özellikler

| Modül | Ne yapar | Durum |
|-------|----------|--------|
| Port Scanner | TCP port tarama (OPEN/CLOSED/FILTERED) | ✅ v1.0 |
| Ping Scanner | CIDR ağında canlı host tespiti | ✅ v1.0 |
| DNS Lookup | A, MX, NS, TXT kayıtları | ✅ v1.0 |
| Whois / IP Info | IP/domain temel bilgi | ✅ v1.0 |
| Log Analyzer | Şüpheli log satırı ayıklama | ✅ v1.0 |
| SSH Failed Login | Auth log brute-force analizi | ✅ v1.0 |
| SNMP Collector | SNMP v2c cihaz bilgisi | ✅ v1.0 |
| Raporlama | TXT / JSON dışa aktarma | ✅ v1.0 |

---
    
## Geliştirme durumu

| Alan | Durum |
|------|--------|
| Çekirdek menü ve modüller | Kararlı (v1.0.0) |
| SNMP v3 | Planlanıyor |
| IPv6 desteği | Planlanıyor |
| GitHub Actions CI build | Planlanıyor |

---

## Yol haritası

- [ ] SNMP v3 kimlik doğrulama
- [ ] IPv6 ping ve port tarama
- [ ] Otomatik GitHub Release build (Linux / macOS / Windows)
- [ ] JSON rapor şeması v2
- [ ] Modül bazlı config dosyası (`config.ini`)

---
## Neden böyle bir proje yazdım?

Günlük network işlerinde sürekli aynı küçük araçları ayrı ayrı açmaktan sıkıldığım için bu projeyi yazmaya başladım.

Bir tarafta port scan,
bir tarafta ping sweep,
başka yerde log kontrolü,
başka yerde SNMP denemesi derken işler dağılabiliyor.

Bu toolkit'in amacı:
sık kullanılan network / audit işlemlerini tek terminal uygulamasında toplamak.

Özellikle:
- sunucu üzerinde SSH ile hızlı kullanım
- düşük kaynak tüketimi
- GUI bağımlılığı olmaması
- hızlı test yapılabilmesi

öncelik alınarak geliştiriliyor.

## Kurulum

```bash
git clone https://github.com/rootars/Network_ToolKit.git
cd Network_ToolKit
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

### Bağımlılıklar

- Python 3.8+
- `colorama`, `dnspython`, `pysnmp`

## Hazır binary indirme

[GitHub Releases](https://github.com/rootars/Network_ToolKit/releases) üzerinden platformunuza uygun ZIP'i indirin:

| Platform | Paket |
|----------|--------|
| Windows | `rootipv6-netaudit-windows-v1.0.0.zip` |
| Linux | `rootipv6-netaudit-linux-v1.0.0.zip` |
| macOS | `rootipv6-netaudit-macos-v1.0.0.zip` |

**Windows:** çıkar → `rootipv6-netaudit.exe` çalıştır

**Linux / macOS:**
```bash
chmod +x rootipv6-netaudit-linux   # veya rootipv6-netaudit-macos
./rootipv6-netaudit-linux
```

### Binary isimleri

| Platform | Dosya |
|----------|--------|
| Linux | `rootipv6-netaudit-linux` |
| macOS | `rootipv6-netaudit-macos` |
| Windows | `rootipv6-netaudit.exe` |

---

## Nuitka build (kaynak koddan)

```bash
pip install -r requirements-build.txt
./build.sh          # Linux / macOS
build.bat           # Windows
```


## License

This project is licensed under the **ROOTIPV6 Community License v1.0**.

Commercial use, rebranding, or redistribution without permission is prohibited.

Tam metin: [LICENSE](LICENSE)



## Modül örnekleri

**Port Scanner:** menü `1` → IP → `22,80,443`

**Ping Scanner:** menü `2` → `192.168.1.0/24`

**DNS Lookup:** menü `3` → `google.com` → kayıt türü

**Raporlama:** önce bir modül çalıştır, menü `8` → TXT veya JSON

---
