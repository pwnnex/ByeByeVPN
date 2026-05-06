# ByeByeVPN

```text
 ____             ____           __     ______  _   _ 
| __ ) _   _  ___| __ ) _   _  __\ \   / /  _ \| \ | |
|  _ \| | | |/ _ \  _ \| | | |/ _ \ \ / /| |_) |  \| |
| |_) | |_| |  __/ |_) | |_| |  __/\ V / |  __/| |\  |
|____/ \__, |\___|____/ \__, |\___| \_/  |_|   |_| \_|
       |___/            |___/                          
   Full TSPU/DPI/VPN detectability scanner   v2.5.7
```

**Discussion / report issues:**
[ntc.party/t/byebyevpn/24325](https://ntc.party/t/byebyevpn/24325) ·
[GitHub Issues](https://github.com/pwnnex/ByeByeVPN/issues)

## Purpose

Given an IP or hostname, run a full detectability methodology plus modern 2026 tunnel fingerprints against it from an external vantage point. Output: a detection score, the identified stack, and what a DPI-class classifier would decide. No VPN connection to the target is needed - the scanner looks at the destination as a third-party observer, the way an ISP or DPI middlebox sees it.

## Pipeline

1. **DNS resolve**: A + AAAA, IPv4 preferred
2. **GeoIP aggregation**: 9 providers in parallel, ASN + flags
3. **TCP port scan**: Connect-scan 1-65535 or curated ports
4. **UDP probes**: Real handshakes (DNS, IKE, OpenVPN, QUIC, WG, Tailscale, L2TP, Hysteria2, TUIC, AmneziaWG)
5. **Service fingerprint + CT**: SSH, HTTP, TLS + SNI consistency, proxies, proxy-header leak
6. **J3 / Active probing**: 8 probes per TLS port (Reality discriminator)
7. **SNITCH + traceroute + SSTP**: RTT vs GeoIP, ICMP hop-count, Microsoft SSTP
8. **Verdict**: Score 0-100, stack identification, hardening advice

## Build

### Linux (CMake + Ninja)
```bash
sudo apt install build-essential cmake ninja-build libssl-dev
git clone https://github.com/pwnnex/ByeByeVPN.git && cd ByeByeVPN
mkdir build && cd build
cmake -G Ninja ..
ninja
```

### Windows (CMake + MSVC)
Open Developer Command Prompt for Visual Studio:
```cmd
git clone https://github.com/pwnnex/ByeByeVPN.git
cd ByeByeVPN
mkdir build
cd build
cmake -G "Visual Studio 17 2022" ..
cmake --build . --config Release
```

## CLI Usage

```bash
byebyevpn                        # interactive menu
byebyevpn <host>                 # full scan
byebyevpn scan 1.2.3.4           # same, explicit
byebyevpn ports my.server.ru     # tcp scan only
byebyevpn udp my.server.ru       # udp probes only
byebyevpn local                  # scan this machine
```

## License

GPLv3. See [LICENSE](LICENSE) for the full license.
This project is a fork of ByeByeVPN and contains code originally licensed under the MIT License by `pwnnex`. See [NOTICE](NOTICE) for the original copyright and permission notices.