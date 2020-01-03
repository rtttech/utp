#include "utp_socket.h"
#include <map>
#include <unordered_map>
#include <assert.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <thread>
#include <time.h>

using namespace rtttech_utp;

static socket_event_callback * g_event_callback = NULL;
static send_data_callback *g_send_proc = NULL;
static std::unordered_map<std::string, UTPSocket*> g_connid2socket_map;
static std::unordered_map<RTSOCKET, std::deque<std::shared_ptr<char>>> g_socket_2_packet_deq;

#include <chrono>


long long get_micro_second()
{
    return GetMicroSecondsSinceEpoch();
}

std::string get_utp_conn_id(uint16_t connid, const char* addr, int len)
{
	std::string uconnid;
	uconnid.append((const char*)&connid, 2);
	uconnid.append(addr, (std::min)(len,8));

	return uconnid;
}

bool generate_conn_id(const char* addr, int len, uint16_t & connid)
{
	srand(time(NULL));
	static uint16_t s_conn_id = rand()%65535;

	for (int i = 0; i < 100; ++i) {
		uint16_t tmp_connid = s_conn_id++;
		
		if (g_connid2socket_map.find(get_utp_conn_id(tmp_connid, addr, len)) == g_connid2socket_map.end()) {
			connid = tmp_connid;
			return true;
		}
	}

	return false;
}

void rt_set_callback(socket_event_callback  *event_cb, send_data_callback *send_cb)
{
	g_event_callback = event_cb;
	g_send_proc = send_cb;
}


void my_send_proc(RTSOCKET socket, const char * buffer, int len, const char* addr, int addr_len)
{
	if (g_send_proc != NULL) {
		g_send_proc(socket, buffer, len, addr, addr_len);
	}
}

bool is_valid_socket(RTSOCKET socket)
{
	return g_socket_2_packet_deq.find(socket) != g_socket_2_packet_deq.end();
}

int rt_init(const char* str, int len)
{
	//static SOCKET 

	return 0;
}

RTSOCKET rt_socket(int mode)
{
	
	UTPSocket *pSocket = new UTPSocket(g_event_callback, my_send_proc, new UTPClock());

	int32_t value = mode;
	pSocket->SetSockOpt(RTSO_MODE, (char*)&value, sizeof(value));

	g_socket_2_packet_deq[pSocket] = std::deque<std::shared_ptr<char>>();

	return (RTSOCKET)pSocket;
}

int rt_connect(RTSOCKET s, const char *to, int tolen)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	uint16_t connid;
	if (!generate_conn_id(to, tolen, connid)) {
		return RTTP_TOO_MUCH_CONNECTION;
	}
	
	pSocket->SetConnID(connid);
	std::string strUTPConnID = get_utp_conn_id(connid, to, tolen);

	g_connid2socket_map[strUTPConnID] = pSocket;

	return pSocket->Connect(to, tolen);
}

int rt_recv(RTSOCKET s, char * buffer, int len, int flag)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	return pSocket->Recv(buffer, len, flag);
}

int rt_send(RTSOCKET s, const char * buffer, int len, int flag)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	return pSocket->Send(buffer, len, flag);
}

void rt_close(RTSOCKET s)
{
	if (!is_valid_socket(s)) {
		return;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	pSocket->Close();
}

int rt_getpeername(RTSOCKET s, char* name, int len)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	const std::string& addr = pSocket->GetRemoteAddr();
	if (len >= addr.size()) {
		memcpy(name, addr.c_str(), addr.size());
		return addr.size();
	}
	else {
		return RTTP_EINSUFFICIENT_BUFFER;
	}
}

int rt_get_error(RTSOCKET s)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	return pSocket->GetError();
}

int rt_connected(RTSOCKET s)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	return pSocket->IsConnected() ? 1 : 0;
}

int rt_writable(RTSOCKET s)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	return pSocket->IsWritable() ? 1 : 0;
}

int rt_readable(RTSOCKET s)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	return pSocket->IsReadable() ? 1 : 0;
}

void* rt_get_userdata(RTSOCKET s)
{
	if (!is_valid_socket(s)) {
		return NULL;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	return pSocket->GetUserData();
}

void rt_set_userdata(RTSOCKET s, void *userdata)
{
	if (!is_valid_socket(s)) {
		return;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	pSocket->SetUserData(userdata);
}

RTSOCKET rt_incoming_packet(const char * buffer, int len, const char *from, int from_len, void* userdata)
{
	if (len < sizeof(PacketHead))
		return 0;

	PacketHead *header = (PacketHead*)buffer;
	if (header->extension != 0) {
		if (len < sizeof(PacketHeadAck))
			return 0;
	}

	header->conn_id = ntohs(header->conn_id);
	header->timestamp = ntohl(header->timestamp);
	header->timestamp_difference = ntohl(header->timestamp_difference);
	header->recv_wnd = ntohl(header->recv_wnd);
	header->pkt_seq = ntohs(header->pkt_seq);
	header->ack_pkt_seq = ntohs(header->ack_pkt_seq);

	
	if (header->GetType() == RTC_SYN) {

		std::string uconnid = get_utp_conn_id(header->conn_id, from, from_len);
		auto iter = g_connid2socket_map.find(uconnid);
		if (iter != g_connid2socket_map.end()) {
			iter->second->OnPacket(buffer, len, from, from_len);
			return nullptr;
		}
		else {
			UTPSocket *pSocket = new UTPSocket(g_event_callback, my_send_proc, new UTPClock(), true);
			pSocket->SetUserData(userdata);

			g_connid2socket_map[uconnid] = pSocket;
			g_socket_2_packet_deq[pSocket] = std::deque<std::shared_ptr<char>>();

			pSocket->OnPacket(buffer, len, from, from_len);

			return (RTSOCKET)pSocket;
		}
	}
	else {
		//initiative connection
		std::string uconnid = get_utp_conn_id(header->conn_id, from, from_len);
		auto iter = g_connid2socket_map.find(uconnid);

		if (iter != g_connid2socket_map.end() && !iter->second->IsPassive()) {
			iter->second->OnPacket(buffer, len, from, from_len);
			return nullptr;
		}

		//passive connection, remote's no syn packet
		uconnid = get_utp_conn_id(header->conn_id - 1, from, from_len);
		iter = g_connid2socket_map.find(uconnid);
		if (iter != g_connid2socket_map.end() && iter->second->IsPassive()) {
			iter->second->OnPacket(buffer, len, from, from_len);
			return nullptr;
		}


	}
	
	return 0;
}

int rt_tick()
{
    int64_t start_time = get_micro_second();
    
	uint32_t connected_num = 0;
	std::unordered_map<std::string, UTPSocket*>::iterator iter;
	for (iter = g_connid2socket_map.begin(); iter != g_connid2socket_map.end();) {

		RTSocketState state = iter->second->State();
		if (state == RTSS_ESTABLISHED) {
			++connected_num;
		}
		if (state != RTSS_CLOSED && state != RTSS_ERROR) {
			iter->second->OnTick();
			++iter;
		}
		else {
			if (iter->second->IsDestroyed()) {
				g_socket_2_packet_deq.erase(iter->second);
				delete iter->second;
				iter = g_connid2socket_map.erase(iter);
			}
			else {
				++iter;
			}
		}
		
	}

    UTPSocket::s_nTotalTickTakeTime = get_micro_second() - start_time;

	return 0;
}

int rt_setsockopt(RTSOCKET s, int optname, void *optval, int optlen)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	return pSocket->SetSockOpt(optname, optval, optlen);
}

int rt_getsockopt(RTSOCKET s, int optname, void *optval, int optlen)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;

	return pSocket->GetSockOpt(optname, optval, optlen);
}


int rt_state_desc(RTSOCKET s, char * desc, int len)
{
	if (!is_valid_socket(s)) {
		return RTTP_EINVALID_SOCKET;
	}

	UTPSocket *pSocket = (UTPSocket*)s;
	std::string strState = pSocket->GetInternalState();

	if (len < strState.size()) {
		return RTTP_EINSUFFICIENT_BUFFER;
	}
	else {
		memcpy(desc, strState.c_str(), strState.size());
		return strState.size();
	}
}

void rt_uninit()
{
	
}
