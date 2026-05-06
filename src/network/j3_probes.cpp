#include "j3_probes.h"
#include "tcp_scanner.h"
#include "../core/utils.h"
#include <openssl/rand.h>
#include <chrono>
#include <cstring>

static J3Result j3_send(const std::string& host, int port, const std::string& name,
                        const void* data, int dlen, bool close_after_send=false) {
    J3Result r; r.name = name;
    auto t0 = std::chrono::steady_clock::now();
    std::string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) return r;
    if (dlen > 0) tcp_send_all(s, data, dlen);
    if (close_after_send) { closesocket(s); return r; }
    char buf[1024]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1200);
    closesocket(s);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    if (n > 0) {
        r.responded = true; r.bytes = n;
        std::string raw(buf, n);
        size_t nl = raw.find('\n');
        r.first_line = trim(raw.substr(0, nl == std::string::npos ? raw.size() : nl));
        r.hex_head = hex_s((unsigned char*)buf, std::min(16, n), true);
    }
    return r;
}

std::vector<J3Result> j3_probes(const std::string& host, int port) {
    std::vector<J3Result> out;
    {
        std::string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
        J3Result r; r.name = "empty/close";
        if (s != INVALID_SOCKET) {
            char buf[128]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 800);
            if (n > 0) { 
                r.responded = true; r.bytes = n; 
                std::string b(buf,n);
                std::string printable;
                for(char c: b) { if (c>=32 && c<127) printable+=c; else printable+='.'; }
                r.first_line = printable; 
                r.hex_head = hex_s((unsigned char*)buf, std::min(16,n), true); 
            }
            closesocket(s);
        }
        out.push_back(r);
    }
    {
        std::string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n";
        out.push_back(j3_send(host, port, "HTTP GET /", req.data(), (int)req.size()));
    }
    {
        std::string req = "CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n";
        out.push_back(j3_send(host, port, "HTTP CONNECT", req.data(), (int)req.size()));
    }
    {
        std::string req = "SSH-2.0-OpenSSH_8.9p1\r\n";
        out.push_back(j3_send(host, port, "SSH banner", req.data(), (int)req.size()));
    }
    {
        unsigned char buf[512]; RAND_bytes(buf, 512);
        out.push_back(j3_send(host, port, "random 512B", buf, 512));
    }
    {
        unsigned char hello[] = {
            0x16,0x03,0x01,0x00,0x70,     
            0x01,0x00,0x00,0x6c,          
            0x03,0x03,                    
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0x00,                         
            0x00,0x02,                    
            0x13,0x02,                    
            0x01,0x00,                    
            0x00,0x41,
            0x00,0x00,0x00,0x10, 0x00,0x0e, 0x00,0x00,0x0b, 0,0,0,'.','i','n','v','a','l','i','d',
            0x00,0x10,0x00,0x0b, 0x00,0x09, 0x08,'h','t','t','p','/','1','.','1',
            0x00,0x0b,0x00,0x02, 0x01,0x00,
            0x00,0x0a,0x00,0x04, 0x00,0x02,0x00,0x1d,
            0x00,0x0d,0x00,0x0a, 0x00,0x08, 0x04,0x01, 0x05,0x01, 0x08,0x07, 0x08,0x08,
            0x00,0x2b,0x00,0x03, 0x02,0x03,0x04,
            0x00,0x33,0x00,0x02, 0x00,0x00
        };
        RAND_bytes(hello + 11, 32);
        for (size_t i = 11 + 32; i + 11 <= sizeof(hello); ++i) {
            if (hello[i]   == '.' && hello[i+1] == 'i' && hello[i+2] == 'n' &&
                hello[i+3] == 'v' && hello[i+4] == 'a' && hello[i+5] == 'l' &&
                hello[i+6] == 'i' && hello[i+7] == 'd' && i >= 3) {
                unsigned char r[3]; RAND_bytes(r, 3);
                hello[i-3] = 'a' + (r[0] % 26);
                hello[i-2] = 'a' + (r[1] % 26);
                hello[i-1] = 'a' + (r[2] % 26);
                break;
            }
        }
        out.push_back(j3_send(host, port, "TLS CH invalid-SNI", hello, (int)sizeof(hello)));
    }
    {
        std::string req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        out.push_back(j3_send(host, port, "HTTP abs-URI (proxy-style)", req.data(), (int)req.size()));
    }
    {
        unsigned char garb[128]; memset(garb, 0xFF, sizeof(garb));
        out.push_back(j3_send(host, port, "0xFF x128", garb, sizeof(garb)));
    }
    return out;
}

static bool looks_like_http_line(const std::string& first_line, bool* bad_version_out = nullptr) {
    if (first_line.size() < 9) return false;
    if (first_line.compare(0, 5, "HTTP/") != 0) return false;
    char x = first_line[5];
    char dot = first_line.size() > 6 ? first_line[6] : 0;
    char y = first_line.size() > 7 ? first_line[7] : 0;
    if (dot != '.') return false;
    bool good_version = ((x=='1' && (y=='0' || y=='1')) || (x=='2' && y=='0'));
    if (!good_version && bad_version_out) *bad_version_out = true;
    return true;
}

J3Analysis j3_analyze(const std::vector<J3Result>& probes) {
    J3Analysis a;
    struct KeyEntry { std::string line; int bytes; const char* name; };
    std::vector<KeyEntry> keys;
    for (auto& p: probes) {
        if (p.responded) {
            ++a.resp;
            keys.push_back({p.first_line, p.bytes, p.name.c_str()});
            bool bad_v = false;
            bool is_http = looks_like_http_line(p.first_line, &bad_v);
            if (is_http && !bad_v) ++a.http_real;
            else if (is_http && bad_v) ++a.http_bad_version;
            else                       ++a.raw_non_http;
        } else {
            ++a.silent;
        }
    }
    auto is_valid_http_probe = [](const char* n) {
        if (!n) return false;
        return strstr(n, "HTTP GET /") != nullptr ||
               strstr(n, "HTTP abs-URI") != nullptr;
    };
    for (size_t i=0; i<keys.size(); ++i) {
        int count = 0;
        bool has_valid_http = false;
        for (size_t j=0; j<keys.size(); ++j) {
            if (keys[i].line == keys[j].line && keys[i].bytes == keys[j].bytes) {
                ++count;
                if (is_valid_http_probe(keys[j].name)) has_valid_http = true;
            }
        }
        if (count >= 2 && keys[i].line.size() > 3 && has_valid_http) {
            a.canned_identical = count;
            a.canned_line      = keys[i].line;
            a.canned_bytes     = keys[i].bytes;
            break;
        }
    }
    return a;
}