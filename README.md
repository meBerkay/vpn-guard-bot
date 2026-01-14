# VPN Guard Bot (Oto-Doğrulama & Oturum Sonlandırma) 🛡️

Bu proje, VPN erişim loglarını e-posta (IMAP) üzerinden izleyen, şüpheli veya mesai dışı erişimlerde kullanıcı kimliğini doğrulayan ve doğrulama yapılmazsa VPN oturumunu Firewall üzerinden otomatik olarak sonlandıran bir **DevSecOps otomasyon aracıdır.**

Özellikle SIEM veya Firewall cihazlarından gelen "Mesai Saati Dışı Erişim" gibi uyarıları işlemek ve SOC ekiplerinin üzerindeki yükü hafifletmek için tasarlanmıştır.

## 🚀 Özellikler

* **Log İzleme:** SIEM veya Firewall'dan gelen e-posta uyarılarını IMAP protokolü ile anlık dinler.
* **Akıllı Log Analizi (Parsing):** Ham e-posta içerisinden (HTML veya Düz Metin) kullanıcı adını, kaynak IP adresini ve zaman damgasını Regex ile ayıklar.
* **Kullanıcı Doğrulama:** İlgili kullanıcıya otomatik bir e-posta göndererek "Bu erişimi siz mi yaptınız?" onayı ister.
* **Aktif Müdahale (Active Response):** Kullanıcı belirlenen süre (Örn: 2 dakika) içinde e-postaya yanıt vermezse, bot otomatik olarak **SSH** üzerinden Firewall'a (FortiGate) bağlanır ve kullanıcının oturumunu sonlandırır (Kill Session).
* **Kendi Kendini Temizleme:** İşlenen ve aksiyon alınan log maillerini hem Gelen Kutusundan (Inbox) hem de Çöp Kutusundan (Trash) silerek posta kutusunu temiz tutar.
* **Modüler & Anonim:** Şirket isimleri, sunucu adresleri ve şifreler kod içinde yer almaz; tamamen `.env` dosyasından yönetilir.

## 🛠️ Kurulum

Bu projeyi Docker kullanarak dakikalar içinde ayağa kaldırabilirsiniz.

### 1. Projeyi Klonlayın
```bash
git clone [https://github.com/kullaniciadiniz/vpn-guard-bot.git](https://github.com/kullaniciadiniz/vpn-guard-bot.git)
cd vpn-guard-bot
