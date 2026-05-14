// SPDX-License-Identifier: GPL-3.0-or-later
// shared windows + winsock include order. include this before any other
// project header in cpp files that touch sockets / iphlpapi / icmp.
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <conio.h>