#include "tcp_scan.h"
#include "../common/winhdr.h"
#include "../net/tcp.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <thread>

using std::string;
using std::vector;

TcpOpen probe_tcp(const string& host, int port, int to_ms) {
    TcpOpen o; o.port = port; o.connect_ms = -1;
    auto t0 = std::chrono::steady_clock::now();
    string err; SOCKET s = tcp_connect(host, port, to_ms, err);
    if (s == INVALID_SOCKET) { o.err = err; return o; }
    o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - t0).count();
    // passive banner grab — some servers talk first (SSH/FTP/SMTP)
    char buf[512]; int n = tcp_recv_to(s, buf, sizeof(buf) - 1, 600);
    if (n > 0) {
        buf[n] = 0;
        o.banner.assign(buf, n);
        while (!o.banner.empty() &&
               (o.banner.back() == '\r' || o.banner.back() == '\n' || o.banner.back() == 0))
            o.banner.pop_back();
    }
    closesocket(s);
    return o;
}

vector<TcpOpen> scan_tcp(const string& host, const vector<int>& ports,
                         int threads, int to_ms, ScanStats* stats) {
    vector<TcpOpen> open;
    std::mutex mx;
    std::atomic<size_t> idx{0};
    std::atomic<int>    done{0};
    std::atomic<size_t> tmo{0}, refused{0}, other{0};
    std::atomic<bool>   abort_scan{false};

    while (_kbhit()) _getch();
    std::fprintf(stderr, "  (press 'q' to skip this phase)\n");

    std::thread kb([&]{
        while (!abort_scan.load()) {
            if (_kbhit()) {
                int c = _getch();
                if (c == 'q' || c == 'Q' || c == 27) {
                    abort_scan = true;
                    break;
                }
            }
            Sleep(50);
        }
    });

    auto worker = [&]{
        while (true) {
            if (abort_scan.load()) break;
            size_t i = idx.fetch_add(1);
            if (i >= ports.size()) break;
            TcpOpen o = probe_tcp(host, ports[i], to_ms);
            int d = ++done;
            size_t cur = 0;
            if (o.connect_ms < 0) {
                if (o.err == "timeout")      ++tmo;
                else if (o.err == "refused") ++refused;
                else                         ++other;
            }
            {
                std::lock_guard<std::mutex> lk(mx);
                if (o.connect_ms >= 0) open.push_back(std::move(o));
                cur = open.size();
            }
            if (d % 20 == 0 || (size_t)d == ports.size()) {
                std::fprintf(stderr, "\r  scanning %d/%zu  open=%zu  ", d, ports.size(), cur);
                std::fflush(stderr);
            }
        }
    };
    threads = std::max(1, std::min(threads, (int)ports.size()));
    vector<std::thread> th;
    for (int i = 0; i < threads; ++i) th.emplace_back(worker);
    for (auto& t: th) t.join();

    abort_scan = true;
    kb.join();

    size_t scanned = std::min(idx.load(), ports.size());
    bool was_skipped = (scanned < ports.size());
    if (was_skipped) {
        std::fprintf(stderr, "\r  scan SKIPPED at %zu/%zu (open=%zu)        \n",
                     scanned, ports.size(), open.size());
    } else {
        std::fprintf(stderr, "\r  scan done (%zu/%zu, open=%zu)        \n",
                     ports.size(), ports.size(), open.size());
    }
    std::sort(open.begin(), open.end(), [](auto& a, auto& b){ return a.port < b.port; });
    if (stats) {
        stats->scanned  = scanned;
        stats->timeouts = tmo.load();
        stats->refused  = refused.load();
        stats->other    = other.load();
        stats->skipped  = was_skipped;
    }
    return open;
}
