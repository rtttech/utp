#pragma once

#ifdef WIN32
#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#else
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <algorithm>
typedef int SOCKET;
#define SOCKET_ERROR -1

#endif

#include <iostream>
#include <string>
#include <string.h>
#include <deque>
#include <memory>

#ifdef _MSC_VER
#define IOCTL ioctlsocket
#else
#define IOCTL ioctl
#endif

struct udp_pkt_send_item
{
	udp_pkt_send_item(const char * data, int size, struct sockaddr * sa, int sock_len)
	{
		buffer = new char[size];
		len = size;
		memcpy(buffer, data, len);
		memcpy(&addr, sa, sock_len);
		addr_len = sock_len;
	}
	~udp_pkt_send_item()
	{
		delete buffer;
	}
	char* buffer;
	int len;
	struct sockaddr_storage addr;
	int addr_len;
};

struct sent_packet_info
{
	sent_packet_info() : send_time(0), resp_time(0), pkt_size(0) {}
	uint64_t send_time;
	uint64_t resp_time;
	uint32_t pkt_size;
};

struct socket_send_item
{
	socket_send_item(const char* buffer, int len) : send_buffer(buffer), send_buff_len(len), send_buff_pos(0) {}
	~socket_send_item() { delete send_buffer; }

	const char* send_buffer;
	int send_buff_pos;
	int send_buff_len;
};

struct socket_io_info
{
	enum state {IDLE, CONNECTING, CONNECTED, WAITING_CLOSE, CLOSED};
	socket_io_info() : recv_buffer(NULL), recv_buff_pos(0), recv_buff_len(0), connected_time(0), create_time(get_micro_second()), state(IDLE) {}
	~socket_io_info() { if (recv_buffer) delete recv_buffer; }

	char* recv_buffer;
	int recv_buff_pos;
	int recv_buff_len;

	uint64_t connected_time;
	uint64_t create_time;
	state state;

	std::deque<std::shared_ptr<socket_send_item>> send_deq;
};

inline void init_socket()
{
#ifdef _MSC_VER
	WSAData wsaData;
	int init_ret = ::WSAStartup(MAKEWORD(2, 2), &wsaData);

#endif
}

inline SOCKET create_udp_socket(int buffer_size = 1024*1024)
{
#ifdef _MSC_VER
	
	SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	u_long arg = 1;
	int ret = ::ioctlsocket(s, FIONBIO, &arg);

#else
	SOCKET s = ::socket(AF_INET, SOCK_DGRAM, 0);
	int oldflags = ::fcntl(s, F_GETFL, 0);
	oldflags |= O_NONBLOCK;
	::fcntl(s, F_SETFL, oldflags);
#endif // _MSC_VER


	int bf = buffer_size;
	int ssrr = setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&bf, (int)sizeof(bf));
	int sssr = setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char*)&bf, (int)sizeof(bf));
	if (ssrr != 0 && sssr != 0) {
		std::cout << "setsockopt failed" << std::endl;
	}
	else {
		//std::cout << "setsockopt success" << std::endl;
	}

	return s;
}

inline SOCKET create_tcp_socket()
{
#ifdef _MSC_VER
    
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, 0);
    
    u_long arg = 1;
    int ret = ::ioctlsocket(s, FIONBIO, &arg);
    
#else
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, 0);
    int oldflags = ::fcntl(s, F_GETFL, 0);
    oldflags |= O_NONBLOCK;
    ::fcntl(s, F_SETFL, oldflags);
#endif // _MSC_VER
    
    return s;
}


inline void close_socket(SOCKET s)
{
#ifdef _MSC_VER
	::closesocket(s);
#else
	::close(s);
#endif
}

inline int get_last_error()
{
#ifdef _MSC_VER
	return ::WSAGetLastError();
#else
	return errno;
#endif
}

inline std::string get_host_ip_address(const char* host)
{
	std::string ret;

	if (inet_addr(host) != -1) {
		ret.assign(host);
		return ret;
	}

	struct addrinfo hints, *res, *p;
	int status;
	char ipstr[INET6_ADDRSTRLEN] = { 0 };

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(host, NULL, &hints, &res)) == 0) {
		for (p = res; p != NULL; p = p->ai_next) {
			void *addr;
			char *ipver;

			// get the pointer to the address itself,
			// different fields in IPv4 and IPv6:
			if (p->ai_family == AF_INET) { // IPv4
				struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
				addr = &(ipv4->sin_addr);
				//ipver = "IPv4";
			}
			else { // IPv6
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
				addr = &(ipv6->sin6_addr);
				//ipver = "IPv6";
			}

			// convert the IP to a string and print it:
			inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
			ret.assign(ipstr);

			break;
		}
	}

	freeaddrinfo(res); // free the linked list

	return ret;
}

template<class OI>
void split_string(const std::string &src_str, OI oi) {
	std::string white_space_str = " \t\n\r\f";

	std::string::size_type last_pos = 0;

	while (last_pos <= src_str.size()) {
		std::string::size_type pos;
		if ((last_pos = src_str.find_first_not_of(white_space_str, last_pos)) == std::string::npos)
			return;

		if ((pos = src_str.find_first_of(white_space_str, last_pos)) == std::string::npos) {
			*oi++ = src_str.substr(last_pos);
			return;
		}
		else {
			*oi++ = src_str.substr(last_pos, pos - last_pos);
			last_pos = pos;
		}
	}
}
