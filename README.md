# ByeByeVPN

Клиентский сканер детектируемости VPN / DPI / Reality / ТСПУ. Одна
статическая `byebyevpn.exe` под Windows (работает через Wine на Linux
и macOS), без прав администратора, без DLL-зависимостей.

```
 ____             ____           __     ______  _   _
| __ ) _   _  ___| __ ) _   _  __\ \   / /  _ \| \ | |
|  _ \| | | |/ _ \  _ \| | | |/ _ \ \ / /| |_) |  \| |
| |_) | |_| |  __/ |_) | |_| |  __/\ V / |  __/| |\  |
|____/ \__, |\___|____/ \__, |\___| \_/  |_|   |_| \_|
       |___/            |___/
   Full TSPU/DPI/VPN detectability scanner   v2.5.6
```

**Languages:** [English](#english) · [Русский](#русский) · [简体中文](README.zh-CN.md) · [فارسی](README.fa.md)

**Discussion / report issues:**
[ntc.party/t/byebyevpn/24325](https://ntc.party/t/byebyevpn/24325) ·
[GitHub Issues](https://github.com/pwnnex/ByeByeVPN/issues)

---

## English

### Purpose

Given an IP or hostname, run the full Russian OCR методика (§5-10) plus
modern 2026 tunnel fingerprints against it from an external vantage
point. Output: a detection score, the identified stack, and what a
TSPU-class classifier would decide. No VPN connection to the target
is needed - the scanner looks at the destination as a third-party
observer, the way an ISP or DPI middlebox sees it.

### Pipeline

| # | Module                          | What it does                                                            |
|---|---------------------------------|-------------------------------------------------------------------------|
| 1 | DNS resolve                     | A + AAAA, IPv4 preferred                                                |
| 2 | GeoIP aggregation               | 9 providers (3 EU / 3 RU / 3 global) in parallel, ASN + flags           |
| 3 | TCP port scan                   | Connect-scan 1-65535 (default) or 205 curated ports, 500 threads        |
| 4 | UDP probes                      | Real handshakes: DNS, IKE, OpenVPN, QUIC, WG, Tailscale, L2TP, Hysteria2, TUIC, AmneziaWG |
| 5 | Service fingerprint + CT        | SSH, HTTP, TLS + SNI consistency, SOCKS5, CONNECT, Shadowsocks, crt.sh, proxy-header leak |
| 6 | J3 / TSPU active probing        | 8 probes per TLS port (Reality discriminator)                           |
| 7 | SNITCH + traceroute + SSTP      | RTT vs GeoIP (methodika §10.1), ICMP hop-count, Microsoft SSTP          |
| 8 | Verdict + TSPU emulation        | Score 0-100, stack identification, 3-tier TSPU ruling, hardening advice |

### UDP handshakes

| Port       | Protocol           | Payload                                               |
|------------|--------------------|-------------------------------------------------------|
| 53         | DNS                | A query for `example.com` (txn id randomized)         |
| 500, 4500  | IKEv2              | ISAKMP SA_INIT header                                 |
| 1194       | OpenVPN            | HARD_RESET_CLIENT_V2                                  |
| 443        | QUIC v1            | 1200-byte Initial (random DCID)                       |
| 51820      | WireGuard          | 148-byte MessageInitiation                            |
| 41641      | Tailscale          | WG-style handshake                                    |
| 1701       | L2TP               | SCCRQ with mandatory AVPs, random tunnel-id           |
| 36712      | Hysteria2          | QUIC v1 Initial, random DCID                          |
| 8443       | TUIC v5            | QUIC v1 Initial                                       |
| 55555      | AmneziaWG Sx=8     | 8-byte junk prefix + WG init                          |
| 51820      | AmneziaWG Sx=8     | Delta-probe: vanilla WG rejected, Sx=8 accepted       |

### J3 probes

Eight probe types fired at every TLS-capable port:

1. Empty TCP connect (no bytes)
2. `GET /` with a real Host header
3. `CONNECT example.com:443`
4. Plausible OpenSSH banner
5. 512 random bytes (via `RAND_bytes`)
6. TLS ClientHello with random `.invalid` SNI
7. Absolute-URI proxy-style `GET`
8. `0xFF × 128`

Reality / XTLS silently drops all 8; regular HTTP returns 400/403. The
pattern is the diagnostic signal.

### Verdict scale

| Score  | Label          | Meaning                                           |
|--------|----------------|---------------------------------------------------|
| 85-100 | `CLEAN`        | Looks like a regular web server                   |
| 70-84  | `NOISY`        | Suspicious artefacts, not necessarily VPN        |
| 50-69  | `SUSPICIOUS`   | Multiple red flags                                |
| < 50   | `OBVIOUSLY VPN`| Trivially detected - obfuscation / stack change needed |

### TSPU emulation

| Tier | Verdict          | Meaning                                                 |
|------|------------------|---------------------------------------------------------|
| A≥1  | `IMMEDIATE BLOCK`| Named protocol signature - SYN/handshake dropped        |
| B≥2  | `BLOCK` (cumul.) | ≥2 soft anomalies - classifier trips block threshold    |
| B=1  | `THROTTLE / QoS` | 1 soft anomaly - flagged for monitoring / rate-limit    |
| 0    | `PASS / ALLOW`   | No signatures                                           |

### On-the-wire posture

The tool does not impersonate a browser. Every outbound HTTP request
(to IP-intel services, to the target during HTTP-over-TLS audit, to
crt.sh) goes out with zero tool-specific headers.

For `http_get()` - the one used against IP-intel services and
crt.sh - the request is byte-wise:

```
GET /path HTTP/1.1
Host: <host>
```

No `User-Agent`, no `Accept`, no `Accept-Language`, no
`Accept-Encoding`, no `Sec-Fetch-*`, no `Upgrade-Insecure-Requests`.
The endpoints all accept a bare GET - the same way `curl -sS
https://ipwho.is/8.8.8.8` works without any flags. WinHTTP still
transparently decompresses gzip'd responses server-side, but we
don't advertise it.

For `https_probe()` - the target HTTP-over-TLS audit - headers are
also minimal (`Host`, `Accept: */*`, `Connection: close`).

Earlier versions (v2.5 - v2.5.4) emitted a Chrome-131 header block
intended to look "browser-like". That was itself a unique static
fingerprint and has been dropped (see
[issue #5](https://github.com/pwnnex/ByeByeVPN/issues/5)).

For protocol probes (UDP handshakes, TLS ClientHello, ICMP) every
field that a real client would randomize is filled via OpenSSL
`RAND_bytes`: OpenVPN session id + timestamp offset, WG ephemeral,
QUIC / Hysteria2 DCID, TLS ClientRandom, invalid-SNI prefix, DNS
transaction id, L2TP tunnel id.

ICMP traceroute payload is the standard Windows `ping.exe` pattern
(`abcdefghi...`, 32 bytes) - byte-identical to what any Windows box
emits.

### Audit

Grep the source for tool-identifying strings. Only three
non-network matches are expected:

```
$ grep -nE 'ByeByeVPN|BYEBYEVPN|BBVPN|BBV|pwnnex' src/byebyevpn.cpp
1:     // ByeByeVPN - full VPN / proxy / Reality detectability analyzer
...    // http_get scrub rationale comment
...    // --help printf
```

None of these reach a socket. The CI workflow
(`.github/workflows/release.yml`) fails the build if any additional
match appears.

### Install

Windows: download `byebyevpn-v2.5.6-win64.zip` from
[Releases](../../releases), extract, run `byebyevpn.exe` - either
double-click for the interactive menu, or pass an IP/hostname from
the terminal.

Runtime: Windows 10 1803+ / 11 / Server 2019+. No admin, no DLLs, no
.NET, no VC++ Redistributable. Internet access for GeoIP and
CT-log lookups.

Linux / macOS: run through Wine. Everything except `local`
(host-side adapter enumeration) works identically.

### CLI

```bash
byebyevpn                        # interactive menu
byebyevpn <host>                 # full scan
byebyevpn scan 1.2.3.4           # same, explicit
byebyevpn ports my.server.ru     # tcp scan only
byebyevpn udp my.server.ru       # udp probes only
byebyevpn tls my.server.ru 443   # tls + sni consistency
byebyevpn j3 my.server.ru 443    # j3 active probing
byebyevpn geoip 8.8.8.8          # geoip aggregation
byebyevpn snitch my.server.ru    # rtt vs geo (methodika §10.1)
byebyevpn trace my.server.ru     # icmp hop-count
byebyevpn local                  # scan this machine
```

Hostnames are resolved via `getaddrinfo`; IPv4 is always preferred,
and the chosen IP is printed in phase [1/8]. On IPv4-only links (RU /
CIS consumer internet) this avoids the happy-eyeballs AAAA trap where
an unreachable v6 silently burns every timeout.

### Port scan modes

```
--full                    all ports 1-65535 (default)
--fast                    205 curated VPN / proxy / TLS / admin ports
--range 8000-9000 ports   port range
--ports 80,443,8443       explicit list
```

### Tuning

```
--threads N       parallel TCP connects      (default 500)
--tcp-to MS       TCP connect timeout         (default 800)
--udp-to MS       UDP recv timeout            (default 900)
--no-color        disable ANSI colors
-v / --verbose    verbose output
```

### Stealth / privacy

```
--stealth         --no-geoip + --no-ct + --udp-jitter (all at once)
--no-geoip        skip all 9 IP-intel lookups
--no-ct           skip crt.sh CT-log query
--udp-jitter      50-300ms random delay between UDP probes
```

All default off. Enable when scanning your own VPS and you don't
want IP-intel services to log the event.

### Build

See [BUILD.md](BUILD.md) for full instructions, OpenSSL provenance,
and SHA256s. Short form:

```bash
# msys2 UCRT64
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-make
git clone https://github.com/pwnnex/ByeByeVPN.git && cd ByeByeVPN
make windows-static
```

Release zips are produced by
[`.github/workflows/release.yml`](.github/workflows/release.yml) from
a pinned msys2 image. SHA256 of the exe and zip are printed in each
release's notes for verification.

### Limitations

- Connect-scan, not SYN-scan. Full TCP handshake seen by the target.
- Cloudflare WARP / CGNAT / corporate proxies can ACK every port
  with identical RTT. The tool detects this (>60 ports with RTT
  variance <80ms) and warns.
- TLS JA3 is OpenSSL-default, not uTLS-Chrome. Reality servers
  in strict uTLS-enforcing mode would reject the handshake. Noted
  in the output as an advisory.
- QUIC probes are version-negotiation only - no derived-key
  handshake. Enough to verify port liveness, not to fingerprint
  the specific QUIC stack.
- GeoIP providers disagree; `ipapi.is` flags any hosting IP as
  "VPN". Score is built on behaviour, not on single-source tags.

### License

MIT. See [LICENSE](LICENSE).

---

## Русский

### Назначение

Получив IP или hostname, программа прогоняет полную методику
Роскомнадзора (§5-10) + современные 2026 сигнатуры обфусцированных
туннелей против этой цели, работая как внешний наблюдатель. На выходе:
score детектируемости, определённый стек, и решение, которое принял
бы ТСПУ-классификатор. Подключаться к VPN цели не нужно - сканер
смотрит на неё так же, как видит провайдер или DPI-middlebox.

### Пайплайн

| # | Модуль                          | Что делает                                                            |
|---|---------------------------------|-----------------------------------------------------------------------|
| 1 | DNS resolve                     | A + AAAA, приоритет IPv4                                              |
| 2 | GeoIP aggregation               | 9 провайдеров (3 EU / 3 RU / 3 global) параллельно, ASN + флаги       |
| 3 | TCP port scan                   | Connect-scan 1-65535 (дефолт) или 205 curated, 500 потоков            |
| 4 | UDP probes                      | Реальные handshake'и: DNS, IKE, OpenVPN, QUIC, WG, Tailscale, L2TP, Hysteria2, TUIC, AmneziaWG |
| 5 | Service fingerprint + CT        | SSH, HTTP, TLS + SNI consistency, SOCKS5, CONNECT, Shadowsocks, crt.sh, proxy-headers |
| 6 | J3 / ТСПУ active probing        | 8 probe'ов на каждый TLS-порт (Reality discriminator)                 |
| 7 | SNITCH + traceroute + SSTP      | RTT vs GeoIP (§10.1), ICMP hop-count, Microsoft SSTP                  |
| 8 | Verdict + эмуляция ТСПУ         | Score 0-100, определение стека, 3-tier вердикт ТСПУ, hardening        |

### UDP handshake'и

| Порт      | Протокол         | Payload                                              |
|-----------|------------------|------------------------------------------------------|
| 53        | DNS              | A-запрос `example.com` (txn id рандомизирован)       |
| 500, 4500 | IKEv2            | ISAKMP SA_INIT header                                |
| 1194      | OpenVPN          | HARD_RESET_CLIENT_V2                                 |
| 443       | QUIC v1          | 1200-байтный Initial (рандомный DCID)                |
| 51820     | WireGuard        | 148-байтный MessageInitiation                        |
| 41641     | Tailscale        | WG-style handshake                                   |
| 1701      | L2TP             | SCCRQ с AVPs, рандомный tunnel-id                    |
| 36712     | Hysteria2        | QUIC v1 Initial, рандомный DCID                      |
| 8443      | TUIC v5          | QUIC v1 Initial                                      |
| 55555     | AmneziaWG Sx=8   | 8-байт junk-prefix + WG init                         |
| 51820     | AmneziaWG Sx=8   | Двойная проба: vanilla WG отвергается, Sx=8 принят   |

### J3 probe'ы

Восемь probe-типов на каждый TLS-порт:

1. Пустой TCP (ничего не шлём)
2. `GET /` с реальным Host-заголовком
3. `CONNECT example.com:443`
4. Плаузабельный OpenSSH-баннер
5. 512 байт `RAND_bytes`
6. TLS ClientHello с рандомным `.invalid` SNI
7. HTTP absolute-URI (proxy-style)
8. `0xFF × 128`

Reality / XTLS молча дропает все 8; обычный HTTP-сервер отвечает
400/403. Сам паттерн и есть сигнал.

### Шкала verdict

| Score  | Label           | Смысл                                                  |
|--------|-----------------|--------------------------------------------------------|
| 85-100 | `CLEAN`         | Выглядит как обычный веб-сервер                        |
| 70-84  | `NOISY`         | Подозрительные артефакты, не обязательно VPN           |
| 50-69  | `SUSPICIOUS`    | Несколько красных флагов                               |
| < 50   | `OBVIOUSLY VPN` | Палится сразу - нужна обфускация / смена стека         |

### Вердикт ТСПУ

| Tier | Вердикт          | Что это значит                                          |
|------|------------------|---------------------------------------------------------|
| A≥1  | `IMMEDIATE BLOCK`| Named-протокол - SYN/handshake дропается                |
| B≥2  | `BLOCK` (cumul.) | ≥2 soft-аномалии - классификатор пересекает порог       |
| B=1  | `THROTTLE / QoS` | 1 soft-аномалия - флаг на мониторинг / rate-limit       |
| 0    | `PASS / ALLOW`   | Нет сигнатур                                            |

### Как тулза выглядит на проводе

Программа не притворяется браузером. Каждый исходящий HTTP-запрос (к
IP-intel сервисам, к target при HTTP-over-TLS аудите, к crt.sh)
уходит **без** tool-specific заголовков.

Для `http_get()` - функция которая ходит в IP-intel и crt.sh -
запрос побайтово выглядит так:

```
GET /path HTTP/1.1
Host: <host>
```

Никаких `User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`,
`Sec-Fetch-*`, `Upgrade-Insecure-Requests`. Эти endpoint'ы принимают
голый GET - так же как работает `curl -sS https://ipwho.is/8.8.8.8`
без дополнительных флагов. WinHTTP всё равно прозрачно распакует
gzip если сервер выберет его сам, но мы не анонсируем поддержку.

Для `https_probe()` - аудит target'а через HTTP-over-TLS - хедеры
тоже минимальные (`Host`, `Accept: */*`, `Connection: close`).

Предыдущие версии (v2.5 - v2.5.4) отправляли блок заголовков "как
Chrome 131", чтобы "выглядеть как браузер". Это само по себе было
уникальным статическим fingerprint'ом и удалено (см.
[issue #5](https://github.com/pwnnex/ByeByeVPN/issues/5)).

Для protocol-probe'ов (UDP handshake'и, TLS ClientHello, ICMP) каждое
поле, которое реальный клиент рандомизирует, заполняется через
OpenSSL `RAND_bytes`: OpenVPN session id + timestamp offset, WG
ephemeral, QUIC / Hysteria2 DCID, TLS ClientRandom, префикс
invalid-SNI, DNS transaction id, L2TP tunnel id.

ICMP traceroute шлёт стандартный Windows `ping.exe` payload
(`abcdefghi...`, 32 байта) - байт-в-байт то же, что и любой
Windows-клиент.

### Аудит

Грепнуть исходник на tool-identifying строки. Ожидаются только три
совпадения, ни одно из которых не уходит в сеть:

```
$ grep -nE 'ByeByeVPN|BYEBYEVPN|BBVPN|BBV|pwnnex' src/byebyevpn.cpp
1:     // ByeByeVPN - full VPN / proxy / Reality detectability analyzer
...    // коммент в http_get про scrub
...    // printf в --help
```

CI workflow (`.github/workflows/release.yml`) проваливает сборку при
любом дополнительном совпадении.

### Установка

Windows: скачать `byebyevpn-v2.5.6-win64.zip` со страницы
[Releases](../../releases), распаковать, запустить `byebyevpn.exe`
(двойной клик = интерактивное меню, либо IP/hostname из терминала).

Требования: Windows 10 1803+ / 11 / Server 2019+. Прав администратора
не нужно. DLL не нужно. Интернет - для GeoIP и CT-log.

Linux / macOS: через Wine. Всё кроме `local` (адаптеры хоста)
работает идентично.

### CLI

```bash
byebyevpn                        # интерактивное меню
byebyevpn <host>                 # полный скан
byebyevpn scan 1.2.3.4           # то же, явно
byebyevpn ports my.server.ru     # только tcp
byebyevpn udp my.server.ru       # только udp
byebyevpn tls my.server.ru 443   # TLS + SNI consistency
byebyevpn j3 my.server.ru 443    # J3 active probing
byebyevpn geoip 8.8.8.8          # GeoIP
byebyevpn snitch my.server.ru    # RTT vs geo (§10.1)
byebyevpn trace my.server.ru     # ICMP hop-count
byebyevpn local                  # сканировать свою машину
```

Hostname резолвится через `getaddrinfo`; IPv4 выбирается всегда, а
выбранный IP печатается в фазе [1/8]. На IPv4-only каналах (РФ / СНГ)
это чинит баг happy-eyeballs, когда недоступный IPv6 тихо съедал
весь timeout.

### Режимы TCP-скана

```
--full                    все порты 1-65535 (дефолт)
--fast                    205 curated VPN / proxy / TLS / admin
--range 8000-9000 ports   диапазон
--ports 80,443,8443       явный список
```

### Тюнинг

```
--threads N       параллельных TCP-connect'ов  (default 500)
--tcp-to MS       TCP connect timeout           (default 800)
--udp-to MS       UDP recv timeout              (default 900)
--no-color        без ANSI-цветов
-v / --verbose    подробный вывод
```

### Stealth / приватность

```
--stealth         --no-geoip + --no-ct + --udp-jitter одновременно
--no-geoip        не дёргать 9 IP-intel сервисов
--no-ct           не дёргать crt.sh
--udp-jitter      50-300ms случайная задержка между UDP probe'ами
```

Все по умолчанию OFF. Включать при сканировании своего VPS, если
не хотите чтобы сторонние сервисы логировали событие.

### Сборка

Смотрите [BUILD.md](BUILD.md) - полные инструкции, provenance OpenSSL,
SHA256. Коротко:

```bash
# msys2 UCRT64
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-make
git clone https://github.com/pwnnex/ByeByeVPN.git && cd ByeByeVPN
make windows-static
```

Релизные zip собираются через
[`.github/workflows/release.yml`](.github/workflows/release.yml) из
pinned msys2 образа. SHA256 exe и zip печатаются в release notes
для верификации.

### Ограничения

- Connect-scan, не SYN-scan. Target видит полный TCP handshake.
- Cloudflare WARP / CGNAT / корпоративный proxy могут ACK'ать любой
  порт с одинаковым RTT. Программа детектит это (>60 портов с
  variance < 80 мс) и выводит warning.
- TLS JA3 = OpenSSL default, не uTLS-Chrome. Reality с жёстким
  uTLS-enforcement отклонит handshake. Отмечено в выводе как advisory.
- QUIC probe - только version negotiation. Достаточно чтобы
  проверить liveness порта, не достаточно чтобы идентифицировать
  конкретный QUIC-стек.
- GeoIP-провайдеры часто несогласны друг с другом; `ipapi.is` метит
  любой hosting-IP как VPN. Score построен на поведении, а не на
  single-source флагах.

### Лицензия

MIT. См. [LICENSE](LICENSE).
