#ifndef NETWORK_SOCKET_SYS_H
#define NETWORK_SOCKET_SYS_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket close

inline int WSAGetLastError() { return errno; }
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAECONNREFUSED ECONNREFUSED
#define WSAETIMEDOUT ETIMEDOUT
#define WSAECONNRESET ECONNRESET

inline void Sleep(int ms) { usleep(ms * 1000); }
#endif

#endif // NETWORK_SOCKET_SYS_H