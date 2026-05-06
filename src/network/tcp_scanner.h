#ifndef NETWORK_TCP_SCANNER_H
#define NETWORK_TCP_SCANNER_H

#include "socket_sys.h"
#include <string>

SOCKET tcp_connect(const std::string& host, int port, int timeout_ms, std::string& err);
int tcp_recv_to(SOCKET s, char* buf, int max, int timeout_ms);
int tcp_send_all(SOCKET s, const void* data, int n);

#endif // NETWORK_TCP_SCANNER_H