#ifndef NETWORK_VPN_PROBES_H
#define NETWORK_VPN_PROBES_H

#include <string>
#include "udp_scanner.h"

UdpResult quic_probe(const std::string& host, int port);
UdpResult openvpn_probe(const std::string& host, int port);
UdpResult wireguard_probe(const std::string& host, int port);
UdpResult ike_probe(const std::string& host, int port);
UdpResult dns_probe(const std::string& host, int port);

#endif // NETWORK_VPN_PROBES_H