#ifndef NETWORK_VPN_PROBES2_H
#define NETWORK_VPN_PROBES2_H

#include "udp_scanner.h"
#include "service_probes.h"
#include <string>

UdpResult hysteria2_probe(const std::string& host, int port);
UdpResult tuic_probe(const std::string& host, int port);
UdpResult l2tp_probe(const std::string& host, int port);
UdpResult amneziawg_probe(const std::string& host, int port);
FpResult sstp_probe(const std::string& host, int port);

#endif // NETWORK_VPN_PROBES2_H