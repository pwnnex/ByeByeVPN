# ByeByeVPN

<div dir="rtl">

اسکنر قابلیت شناسایی VPN / DPI / Reality / ТСПУ. یک فایل اجرایی
ایستا `byebyevpn.exe` برای Windows (روی Linux و macOS از طریق Wine
کار می‌کند)، بدون نیاز به مجوز مدیر، بدون وابستگی به DLL.

</div>

```
 ____             ____           __     ______  _   _
| __ ) _   _  ___| __ ) _   _  __\ \   / /  _ \| \ | |
|  _ \| | | |/ _ \  _ \| | | |/ _ \ \ / /| |_) |  \| |
| |_) | |_| |  __/ |_) | |_| |  __/\ V / |  __/| |\  |
|____/ \__, |\___|____/ \__, |\___| \_/  |_|   |_| \_|
       |___/            |___/
   Full TSPU/DPI/VPN detectability scanner   v2.5.5
```

**زبان‌ها / Languages:** [English](README.md) · [Русский](README.md#русский) · [简体中文](README.zh-CN.md) · [فارسی](#فارسی)

**بحث و گزارش مشکل / Discussion:**
[ntc.party/t/byebyevpn/24325](https://ntc.party/t/byebyevpn/24325) ·
[GitHub Issues](https://github.com/pwnnex/ByeByeVPN/issues)

---

## فارسی

<div dir="rtl">

### هدف

با ورود یک IP یا نام میزبان، این ابزار به عنوان یک ناظر خارجی،
متدولوژی کامل روسی OCR (§5-10) به علاوه اثر انگشت تونل‌های مدرن
سال ۲۰۲۶ را روی هدف اجرا می‌کند. خروجی: امتیاز قابلیت شناسایی،
پشتهٔ شناسایی‌شده، و حکمی که یک طبقه‌بند سطح TSPU صادر می‌کرد.
**نیازی به اتصال VPN به هدف نیست** - اسکنر هدف را از بیرون نگاه
می‌کند، دقیقاً همان‌طور که یک ISP یا جعبهٔ میانی DPI می‌بیند.

### خط لوله

</div>

| # | ماژول                                  | کار                                                                       |
|---|----------------------------------------|---------------------------------------------------------------------------|
| 1 | DNS resolve                            | A + AAAA، اولویت با IPv4                                                  |
| 2 | GeoIP aggregation                      | ۹ ارائه‌دهنده (۳ EU / ۳ RU / ۳ جهانی) به‌صورت موازی، ASN + پرچم‌ها         |
| 3 | TCP port scan                          | اسکن connect پورت ۱-۶۵۵۳۵ (پیش‌فرض) یا ۲۰۵ پورت منتخب، ۵۰۰ رشته           |
| 4 | UDP probes                             | handshake واقعی: DNS / IKE / OpenVPN / QUIC / WG / Tailscale / L2TP / Hysteria2 / TUIC / AmneziaWG |
| 5 | Service fingerprint + CT               | SSH, HTTP, TLS + SNI consistency, SOCKS5, CONNECT, Shadowsocks, crt.sh, نشت هدر پراکسی |
| 6 | J3 / TSPU active probing               | ۸ probe روی هر پورت TLS (تشخیص‌دهندهٔ Reality)                             |
| 7 | SNITCH + traceroute + SSTP             | RTT vs GeoIP (§10.1)، hop-count ICMP، Microsoft SSTP                     |
| 8 | Verdict + شبیه‌سازی TSPU               | امتیاز ۰-۱۰۰، شناسایی پشته، حکم ۳-سطحی TSPU، پیشنهاد سخت‌سازی              |

### UDP handshakes

| پورت       | پروتکل          | محموله                                                         |
|------------|-----------------|----------------------------------------------------------------|
| 53         | DNS             | پرس‌وجوی A برای `example.com` (txn id تصادفی)                  |
| 500, 4500  | IKEv2           | هدر ISAKMP SA_INIT                                             |
| 1194       | OpenVPN         | HARD_RESET_CLIENT_V2                                           |
| 443        | QUIC v1         | Initial ۱۲۰۰ بایتی (DCID تصادفی)                               |
| 51820      | WireGuard       | MessageInitiation ۱۴۸ بایتی                                    |
| 41641      | Tailscale       | handshake به سبک WG                                            |
| 1701       | L2TP            | SCCRQ با AVPهای الزامی، tunnel-id تصادفی                        |
| 36712      | Hysteria2       | QUIC v1 Initial، DCID تصادفی                                   |
| 8443       | TUIC v5         | QUIC v1 Initial                                                |
| 55555      | AmneziaWG Sx=8  | پیشوند ۸ بایتی مزاحم + WG init                                 |
| 51820      | AmneziaWG Sx=8  | probe مقایسه‌ای: WG اصلی رد می‌شود، Sx=8 پذیرفته می‌شود        |

<div dir="rtl">

### probeهای J3

هشت نوع probe روی هر پورت پشتیبان TLS:

۱. اتصال TCP خالی (هیچ بایتی ارسال نمی‌شود)  
۲. `GET /` با هدر Host واقعی  
۳. `CONNECT example.com:443`  
۴. بنر منطقی OpenSSH  
۵. ۵۱۲ بایت تصادفی (`RAND_bytes`)  
۶. TLS ClientHello با SNI تصادفی `.invalid`  
۷. درخواست HTTP به سبک پراکسی با URI مطلق  
۸. `0xFF × 128`

Reality / XTLS هر ۸ مورد را بی‌صدا رها می‌کند؛ HTTP عادی پاسخ
400/403 می‌دهد. **خود الگو** سیگنال تشخیص است.

### مقیاس حکم

</div>

| امتیاز  | برچسب           | معنی                                                  |
|---------|-----------------|-------------------------------------------------------|
| 85-100  | `CLEAN`         | شبیه یک وب سرور معمولی است                            |
| 70-84   | `NOISY`         | آثار مشکوک، لزوماً VPN نیست                           |
| 50-69   | `SUSPICIOUS`    | چند پرچم قرمز                                         |
| < 50    | `OBVIOUSLY VPN` | به سادگی شناسایی می‌شود - نیاز به obfuscation/تغییر پشته |

### شبیه‌سازی TSPU

| سطح  | حکم              | معنی                                                       |
|------|------------------|------------------------------------------------------------|
| A≥1  | `IMMEDIATE BLOCK`| امضای پروتکل نام‌دار - SYN/handshake دور انداخته می‌شود    |
| B≥2  | `BLOCK` (تجمعی)  | ≥۲ ناهنجاری نرم - طبقه‌بند آستانه مسدودسازی را رد می‌کند  |
| B=1  | `THROTTLE / QoS` | ۱ ناهنجاری نرم - پرچم نظارت / محدودیت نرخ                 |
| 0    | `PASS / ALLOW`   | هیچ امضایی نیست                                            |

<div dir="rtl">

### رفتار روی سیم

ابزار **خود را به عنوان مرورگر جا نمی‌زند**. هر درخواست HTTP خروجی
(به سرویس‌های IP-intel، به هدف در حین بازبینی HTTP-over-TLS، به
crt.sh) **بدون** هدر خاص ابزار ارسال می‌شود.

برای `http_get()` (استفاده شده برای IP-intel و crt.sh)، درخواست
بایت به بایت به این شکل است:

</div>

```
GET /path HTTP/1.1
Host: <host>
```

<div dir="rtl">

**هیچ** `User-Agent`، `Accept`، `Accept-Language`، `Accept-Encoding`،
`Sec-Fetch-*`، `Upgrade-Insecure-Requests` ارسال نمی‌شود. این نقاط
پایانی یک GET خالی را می‌پذیرند - دقیقاً همان‌طور که `curl -sS
https://ipwho.is/8.8.8.8` بدون هیچ flag کار می‌کند. اگر سرور خودش
gzip را انتخاب کند، WinHTTP همچنان به‌طور شفاف آن را باز می‌کند،
اما ما پشتیبانی از آن را اعلام نمی‌کنیم.

برای `https_probe()` (بازبینی HTTP-over-TLS هدف)، هدرها نیز حداقلی
هستند (`Host`، `Accept: */*`، `Connection: close`).

نسخه‌های قبلی (v2.5 تا v2.5.4) بلوک هدر «شبیه Chrome-131» می‌فرستادند
تا «شبیه مرورگر به نظر برسد». این خودش یک **اثر انگشت ایستا و
منحصر به فرد** بود و حذف شد (
[issue #5](https://github.com/pwnnex/ByeByeVPN/issues/5)).

برای probeهای پروتکل (UDP handshake، TLS ClientHello، ICMP) هر
فیلدی که کلاینت واقعی تصادفی می‌کند، با OpenSSL `RAND_bytes` پر
می‌شود: session id + offset زمان OpenVPN، ephemeral WG، DCID
QUIC / Hysteria2، ClientRandom TLS، پیشوند invalid-SNI، transaction
id DNS، tunnel id L2TP.

محموله ICMP traceroute همان الگوی استاندارد `ping.exe` ویندوز است
(`abcdefghi...`، ۳۲ بایت) - بایت به بایت مثل چیزی که هر کلاینت
ویندوز می‌فرستد.

### بازبینی

برای رشته‌های شناسایی‌کنندهٔ ابزار در سورس grep بزنید. تنها سه
تطابق غیرشبکه‌ای انتظار می‌رود:

</div>

```
$ grep -nE 'ByeByeVPN|BYEBYEVPN|BBVPN|BBV|pwnnex' src/byebyevpn.cpp
1:     // ByeByeVPN - full VPN / proxy / Reality detectability analyzer
...    // کامنت http_get درباره scrub
...    // printf در --help
```

<div dir="rtl">

هیچ‌کدام به سوکت نمی‌رسند. جریان کار CI
(`.github/workflows/release.yml`) در صورت وجود هر تطابق اضافی
build را fail می‌کند.

### نصب

Windows: `byebyevpn-v2.5.5-win64.zip` را از
[Releases](../../releases) دانلود کنید، باز کنید، `byebyevpn.exe`
را اجرا کنید (دابل‌کلیک = منوی تعاملی، یا IP/نام میزبان از ترمینال).

الزامات: Windows 10 1803+ / 11 / Server 2019+. نیازی به مدیر نیست.
نیازی به DLL نیست. نیازی به .NET یا VC++ Redistributable نیست.
اینترنت برای GeoIP و CT-log.

Linux / macOS: از طریق Wine. همه چیز به جز `local` (شمارش آداپتور
میزبان) کاملاً یکسان کار می‌کند.

### CLI

</div>

```bash
byebyevpn                        # منوی تعاملی
byebyevpn <host>                 # اسکن کامل
byebyevpn scan 1.2.3.4           # همان، صریح
byebyevpn ports my.server.ru     # فقط TCP
byebyevpn udp my.server.ru       # فقط UDP
byebyevpn tls my.server.ru 443   # TLS + SNI consistency
byebyevpn j3 my.server.ru 443    # probing فعال J3
byebyevpn geoip 8.8.8.8          # GeoIP
byebyevpn snitch my.server.ru    # RTT vs geo (§10.1)
byebyevpn trace my.server.ru     # hop-count ICMP
byebyevpn local                  # اسکن ماشین محلی
```

<div dir="rtl">

نام میزبان با `getaddrinfo` resolve می‌شود؛ **همیشه** IPv4 ترجیح
داده می‌شود و IP انتخاب‌شده در فاز [1/8] چاپ می‌شود. روی لینک‌های
IPv4-only (اینترنت خانگی RU / CIS) این رفتار از تلهٔ happy-eyeballs
AAAA جلوگیری می‌کند - یک v6 غیرقابل دسترس به‌طور بی‌صدا کل
timeout را می‌سوزاند.

### حالت‌های اسکن پورت

</div>

```
--full                    همه پورت‌ها ۱-۶۵۵۳۵ (پیش‌فرض)
--fast                    ۲۰۵ پورت منتخب VPN / پراکسی / TLS / ادمین
--range 8000-9000 ports   محدوده پورت
--ports 80,443,8443       لیست صریح
```

### تنظیم

```
--threads N       اتصالات TCP موازی    (پیش‌فرض ۵۰۰)
--tcp-to MS       timeout اتصال TCP    (پیش‌فرض ۸۰۰)
--udp-to MS       timeout دریافت UDP   (پیش‌فرض ۹۰۰)
--no-color        غیرفعال کردن رنگ ANSI
-v / --verbose    خروجی مفصل
```

### حالت مخفی / حریم خصوصی

```
--stealth         --no-geoip + --no-ct + --udp-jitter با هم
--no-geoip        رد کردن همه ۹ جستجوی IP-intel
--no-ct           رد کردن جستجوی crt.sh CT-log
--udp-jitter      تأخیر تصادفی ۵۰-۳۰۰ میلی‌ثانیه بین probeهای UDP
```

<div dir="rtl">

همه پیش‌فرض خاموش. زمانی که VPS خودتان را اسکن می‌کنید و
نمی‌خواهید سرویس‌های شخص ثالث این رویداد را ثبت کنند، فعال کنید.

### Build

جزئیات کامل، provenance OpenSSL و SHA256 در [BUILD.md](BUILD.md).
کوتاه:

</div>

```bash
# msys2 UCRT64
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-make
git clone https://github.com/pwnnex/ByeByeVPN.git && cd ByeByeVPN
make windows-static
```

<div dir="rtl">

zipهای release توسط
[`.github/workflows/release.yml`](.github/workflows/release.yml) از
ایمیج pinned msys2 ساخته می‌شوند. SHA256 فایل exe و zip در
release notes هر tag برای تأیید چاپ می‌شود.

### محدودیت‌ها

- اسکن connect، نه SYN. هدف یک handshake کامل TCP می‌بیند.
- Cloudflare WARP / CGNAT / پراکسی‌های سازمانی ممکن است هر پورت را
  با RTT یکسان ACK کنند. ابزار این را تشخیص می‌دهد (>۶۰ پورت با
  واریانس RTT <۸۰ms) و هشدار می‌دهد.
- TLS JA3 پیش‌فرض OpenSSL است، نه uTLS-Chrome. سرورهای Reality در
  حالت uTLS سختگیرانه handshake را رد می‌کنند. در خروجی به عنوان
  advisory علامت‌گذاری می‌شود.
- probe QUIC فقط مذاکره نسخه است - handshake کلید مشتق شده ندارد.
  برای تأیید فعال بودن پورت کافی است، برای شناسایی پشته خاص QUIC
  کافی نیست.
- ارائه‌دهندگان GeoIP اختلاف نظر دارند؛ `ipapi.is` هر IP میزبانی را
  «VPN» برچسب می‌زند. امتیاز بر اساس رفتار است، نه برچسب تک-منبعی.

### مجوز

MIT. [LICENSE](LICENSE) را ببینید.

</div>
