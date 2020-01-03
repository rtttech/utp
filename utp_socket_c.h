#if !defined(RTSOCKET_H__FB063327_573C_4D70_A0B4_ECC067B6F4FD__INCLUDED_)
#define RTSOCKET_H__FB063327_573C_4D70_A0B4_ECC067B6F4FD__INCLUDED_

//mode
#define RTSM_LOW_LATENCY		0
#define RTSM_HIGH_THROUGHPUT	1

//
#define RTSO_MTU				0x10001
#define RTSO_FEC				0x10002
#define RTSO_FAST_ACK			0x10003
#define RTSO_RCVBUF				0x10004

//get only param
#define RTSO_RTT				0x20001
#define RTSO_LOST_RATE			0x20002
#define RTSO_RECENT_LOST_RATE	0x20003

//set only param
#define RTSO_MODE				0x30001

#define RTTP_EWOULDBLOCK			-1

#define RTTP_EINVAL					-100
#define RTTP_ENOTCONN				-101
#define RTTP_ECONNABORTED			-102
#define RTTP_ETIMEDOUT				-103
#define RTTP_ECONNRESET				-104
#define RTTP_EINVALID_SOCKET		-105
#define RTTP_EINSUFFICIENT_BUFFER	-106
#define RTTP_TOO_MUCH_CONNECTION	-107

#if defined(RTDLL)
#if defined(_MSC_VER)
    #define RTEXPORT __declspec(dllexport)
#else
    #define RTEXPORT __attribute__((visibility("default")))
#endif
#else
#define RTEXPORT
#endif

#define RTTP_EVENT_CONNECT	1
#define RTTP_EVENT_READ		2
#define RTTP_EVENT_WRITE	3
#define RTTP_EVENT_ERROR	4


#if defined(__cplusplus)
extern "C"
{
#endif
	RTEXPORT long long get_micro_second();

	typedef void* RTSOCKET;

	typedef void socket_event_callback(RTSOCKET socket, int event);
	typedef void send_data_callback(RTSOCKET socket, const char * buffer, int len, const char* addr, int addr_len);


	RTEXPORT void rt_set_callback(socket_event_callback *event_callback, send_data_callback *sendproc);

	RTEXPORT int rt_init(const char* str, int len);
	RTEXPORT RTSOCKET rt_socket(int mode);
	RTEXPORT int rt_connect(RTSOCKET s, const char *to, int tolen);
	RTEXPORT int rt_recv(RTSOCKET s, char * buffer, int len, int flag);
	RTEXPORT int rt_send(RTSOCKET s, const char * buffer, int len, int flag);
	RTEXPORT void rt_close(RTSOCKET s);

	RTEXPORT RTSOCKET rt_incoming_packet(const char * buffer, int len, const char *from, int fromlen, void* userdata);
	RTEXPORT int rt_tick();

	RTEXPORT int rt_getpeername(RTSOCKET s, char* name, int len);
	RTEXPORT int rt_get_error(RTSOCKET s);
	RTEXPORT int rt_connected(RTSOCKET s);
	RTEXPORT int rt_writable(RTSOCKET s);
	RTEXPORT int rt_readable(RTSOCKET s);
	RTEXPORT int rt_setsockopt(RTSOCKET s, int optname, void *optval, int optlen);
	RTEXPORT int rt_getsockopt(RTSOCKET s, int optname, void *optval, int optlen);

	RTEXPORT void* rt_get_userdata(RTSOCKET s);
	RTEXPORT void rt_set_userdata(RTSOCKET s, void *userdata);

	RTEXPORT int rt_state_desc(RTSOCKET s, char * desc, int len);

	RTEXPORT void rt_uninit();

#if defined(__cplusplus)
}
#endif


#endif
