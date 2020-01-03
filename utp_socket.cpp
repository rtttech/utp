#include "utp_socket.h"
#include "log_helper.h"

#include <string.h>
#include <algorithm>
#include <sstream>
#include <time.h>
#include <vector>

namespace rtttech_utp
{

using namespace std;

static const uint32_t MAX_SYN_RESEND_TIMES = 5;
static const uint32_t MAX_CLOSE_RESEND_TIMES = 10;
static const int MAX_SACK_BYTES = 100;
static const uint32_t DEFAULT_LOCAL_RECV_WINDOW = 1024*1024;
static LogHelper gHelper;

DECLARE_LOG("UTPSocket", "utp_log.txt")

static int GenerateAckBitfield(CircleSeq<uint16_t> next_expect, const std::map<CircleSeq<uint16_t>, std::shared_ptr<PacketCS>>& pkt_map, char* buff, int size)
{
	RTASSERT(size % 4 == 0);

	std::vector<CircleSeq<uint16_t>> seqvec;
	seqvec.reserve(pkt_map.size());

	std::map<CircleSeq<uint16_t>, std::shared_ptr<PacketCS>>::const_iterator iter;
	for (iter = pkt_map.cbegin(); iter != pkt_map.cend(); ++iter) {
		seqvec.push_back(iter->first);
	}

	if (size > MAX_SACK_BYTES) {
		size = MAX_SACK_BYTES;
	}

	return GenerateAckBitfield(next_expect, seqvec, buff, size);
}

static int GetBitmapBits(CircleSeq<uint16_t> next_expect, const std::map<CircleSeq<uint16_t>, std::shared_ptr<PacketCS>>& pkt_map)
{
	if (pkt_map.size() == 0)
        return 0;

	int bits = GetBitmapBits(next_expect, pkt_map.rbegin()->first, pkt_map.size());

	return (std::min)(bits, MAX_SACK_BYTES * 8);
}

static int GetBitmapBytes(CircleSeq<uint16_t> next_expect, const std::map<CircleSeq<uint16_t>, std::shared_ptr<PacketCS>>& pkt_map)
{

	int nBitmapBits = GetBitmapBits(next_expect, pkt_map);
	int nBitmapBytes = (nBitmapBits + 7) / 8;

	int nLeftBytes = nBitmapBytes % 4;
	if (nLeftBytes != 0) {
		nBitmapBytes += 4 - nLeftBytes;
	}

	RTASSERT(nBitmapBytes % 4 == 0);

	return nBitmapBytes;
}

static int GetBitmapExtensionBytes(int bitmap_bytes)
{
	RTASSERT(bitmap_bytes % 4 == 0);

	if (bitmap_bytes == 0)
		return 0;
	else
		return 2 + bitmap_bytes;
}

void HeaderToBigEndian(PacketHead* pHead)
{
	pHead->conn_id = ntohs(pHead->conn_id);
	pHead->timestamp = ntohl(pHead->timestamp);
	pHead->timestamp_difference = ntohl(pHead->timestamp_difference);
	pHead->recv_wnd = ntohl(pHead->recv_wnd);
	pHead->pkt_seq = ntohs(pHead->pkt_seq);
	pHead->ack_pkt_seq = ntohs(pHead->ack_pkt_seq);
}

static std::string StateDesc(RTSocketState s)
{
	const char *desc[] = { "IDLE", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "CLOSING", "CLOSE_WAIT", "CLOSED", "ERROR" };
	
	return desc[s];
}

static std::string PacketDesc(const PacketHead *pHeader)
{
	std::ostringstream oss;
	
	oss << "packet, cmd "; 
	if (pHeader->GetType() == RTC_SYN) {
		oss << "SYN";
	}
	else if (pHeader->GetType() == RTC_DATA) {
		oss << "DATA";
	}
	else if (pHeader->GetType() == RTC_STATE) {
		oss << "STATE";
	}
	else if (pHeader->GetType() == RTC_FIN) {
		oss << "FIN";
	}
	else if (pHeader->GetType() == RTC_RESET) {
		oss << "RESET";
	}
	else {
		oss << "unknown packet";
	}
	oss << " conn_id: " << pHeader->conn_id << " pkt_seq: " << pHeader->pkt_seq << " bytes_seq: "
		<< " recv_wnd: " << pHeader->recv_wnd << " ack_pkt_seq: "
		<< pHeader->ack_pkt_seq << " send pkt seq: " << pHeader->pkt_seq;
		
	if (pHeader->extension != 0) {
		PacketHeadAck *pHeaderAck = (PacketHeadAck *)pHeader;
		oss <<" bitmap bytes: "<<(int)pHeaderAck->ext_len;
	}
	return oss.str();
}

uint32_t UTPSocket::s_nTotalTickTakeTime = 0;
    
UTPSocket::UTPSocket(socket_event_callback *cb, send_data_callback *pfsend, UTPClock* clock, bool passive)
	:
	m_bDestroyed(false),
	m_pUserdata(NULL),
	m_pfCallBack(cb),
	m_pfSendProc(pfsend),
	m_nMtu(1200),
	m_nLocalExpectPktSeq(1),
	m_nLocalSendPktSeq(1),
	m_nLocalSendBytesSeq(0),
	m_nLocalRecvWnd(DEFAULT_LOCAL_RECV_WINDOW),
	m_nSendSeq(0),
	m_nRemoteAckedPktSeq(0),
	m_nRemoteExpectBytesSeq(0),
    m_nRemoteRecvWnd(0),
	m_nLocalExpectBytesSeq(0),
	m_nReadableBytes(0),
	m_nNotReadableBytes(0),
	m_nNotAckedDataBytes(0),
	m_nTotalPktNum(0),
	m_nFoundLostPktNum(0),
	m_nTotalSendTimes(0),
	m_nError(0),
	m_eState(RTSS_IDLE),
	m_nStateChangeTime(0),
	m_bWaitWrite(false),
	m_bWaitRead(true),
	m_bWaitConnect(true),
	m_bEnableFec(false),
	m_bFastAck(false),
	m_bDelayAck(false),
	m_nLastSendFec(0),
	m_nLastReceivedTime(0),
	m_nLastSendAck(0),
	m_nConnTimeoutTime(30*1000*1000),
	m_nAckInterval(100*1000),
	m_nTheirTimestampDiff(0),
	m_nMyTimestampDiff(0),
	m_ptrCongestionController(NULL),
	m_ptrRoundTripMeter(NULL),
	m_bPassive(passive)
{
	
	LOG_DEBUG(logger, "{} UTPSocket::UTPSocket", (void*)this);


	m_nRemoteAckedPktSeq = m_nLocalSendPktSeq;
	m_nRemoteExpectBytesSeq = m_nLocalSendBytesSeq;

	//m_ptrCongestionController = new NullCongestionController(512);
	m_ptrCongestionController.reset(new LedbatCongestionController(m_nMtu, m_nMtu, 100*1000));
	m_ptrRoundTripMeter.reset(new SimpleRoundTripMeter());

	m_ptrPacketLostCounter.reset(new LostCounter(3*1000*1000, 20));
	m_ptrClocker.reset(clock);

	m_nLastReceivedTime = m_ptrClocker->GetMicroSecond();
	m_nLastSendAck = m_ptrClocker->GetMicroSecond();
}

UTPSocket::~UTPSocket()
{
	LOG_DEBUG(logger, "{} UTPSocket::~UTPSocket", (void*)this);

	LOG_INFO(logger, "{} total pkt num: {}, lost num: {}, total send times: {}", (void*)this, m_nTotalPktNum, m_nFoundLostPktNum, m_nTotalSendTimes);
}

void UTPSocket::ChangeToState(RTSocketState s)
{
	LOG_INFO(logger, "{} change to state {}", (void*)this, StateDesc(s));
	m_eState = s;
	m_nStateChangeTime = m_ptrClocker->GetMicroSecond();

	if (s == RTSS_CLOSED || s == RTSS_ERROR) {
		return;//for debug
	}
}

int UTPSocket::Connect(const char *to, int tolen)
{
	LOG_DEBUG(logger, "{} UTPSocket::Connect", (void*)this);

	if (m_eState != RTSS_IDLE) {
		return RTTP_EINVAL;
	}

	if (to != NULL && tolen > 0)
		m_strRemoteAddr.assign(to, tolen);

	SendSyn();

	ChangeToState(RTSS_SYN_SENT);

	return 0;
}

int UTPSocket::Recv(char * buffer, int len, int flag)
{

	if (m_eState != RTSS_ESTABLISHED && m_eState != RTSS_CLOSED && m_eState != RTSS_CLOSE_WAIT) {
		if (m_nError != 0) {
			return m_nError;
		}
		else {
			return RTTP_EWOULDBLOCK;
		}
	}

	if (m_nReadableBytes == 0) {
		if (m_eState == RTSS_ESTABLISHED) {
			m_bWaitRead = true;
			return RTTP_EWOULDBLOCK;
		}
		else if (m_eState == RTSS_CLOSED || m_eState == RTSS_CLOSE_WAIT) {
			return 0;
		}
		else {
			RTASSERT(false);
		}
	}
	else {
		m_bWaitRead = false;
	}

	RTASSERT(m_deqReady4ReadPacket.size() > 0);
	std::shared_ptr<PacketCS> pkt = m_deqReady4ReadPacket[0];

	RTASSERT(pkt->len > pkt->pos);
	int nCopyLen = (std::min)(len, pkt->len - pkt->pos);
	RTASSERT(nCopyLen > 0);
	memcpy(buffer, pkt->buffer + pkt->pos, nCopyLen);
	pkt->pos += nCopyLen;

	if (pkt->pos >= pkt->len) {
		RTASSERT(pkt->pos == pkt->len);
		m_deqReady4ReadPacket.pop_front();
	}
	
	uint32_t nRecvWndBefore = GetLeftRecvWndBytes();

	RTASSERT(m_nReadableBytes >= nCopyLen);
	m_nReadableBytes -= nCopyLen;
	
	if (nRecvWndBefore == 0) {
		SendState();
	}

	LOG_DEBUG(logger, "{} user recv return {} bytes", (void*)this, nCopyLen);

	return nCopyLen;
}

int UTPSocket::Send(const char * buffer, int len, int flag)
{
	if (m_eState != RTSS_ESTABLISHED) {
		if (m_nError != 0) {
			return m_nError;
		}
		else {
			return RTTP_EWOULDBLOCK;
		}
	}

	int nAllowWriteBytes = GetAllowWriteBytes();

	LOG_INFO(logger, "{} user send data {} bytes, current congetstion wnd value:{}, current allow:{}, not acked size:{}", (void*)this,
		len, m_ptrCongestionController->GetCongestionWnd(), nAllowWriteBytes, m_nNotAckedDataBytes);

	if (nAllowWriteBytes < 0)
		nAllowWriteBytes = 0;

	int nLeftLen = (std::min)(len, nAllowWriteBytes);
	int nSentLen = 0;
	

	while (nLeftLen > 0) {
		int nCurSend = (std::min)((int)m_nMtu, nLeftLen);
		SendData(buffer + nSentLen, nCurSend, flag);
		nLeftLen -= nCurSend;
		nSentLen += nCurSend;
	}

	if (nSentLen < len) {
		m_bWaitWrite = true;
	}
	else {
		m_bWaitWrite = false;
	}

	if (nSentLen == 0) {
		return RTTP_EWOULDBLOCK;
	}
	

	LOG_INFO(logger, "{} user send data {} bytes, current congetstion wnd value:{}, send return {}, not acked size:{}", (void*)this,
		len, m_ptrCongestionController->GetCongestionWnd(), nSentLen, m_nNotAckedDataBytes);

	return nSentLen;
}

void UTPSocket::Close()
{
	LOG_DEBUG(logger, "{} UTPSocket::Close", (void*)this);

	m_bWaitRead = false;
	m_bWaitWrite = false;
	m_bWaitConnect = false;

	m_bDestroyed = true;

	m_pfCallBack = nullptr;

	if (m_eState == RTSS_CLOSING || m_eState == RTSS_CLOSED) {
		return;
	}

	if (m_eState == RTSS_SYN_SENT || m_eState == RTSS_SYN_RECEIVED) {
		SendClose(false);
		ChangeToState(RTSS_CLOSING);
	}
	else if (m_eState == RTSS_ESTABLISHED) {
		if (m_deqNotAckedDataPacket.size() == 0) {
			SendClose(false);
		}
		ChangeToState(RTSS_CLOSING);//local close connection
	}
	else {
		ChangeToState(RTSS_CLOSED);
	}
}

bool UTPSocket::IsReadable()
{
	if (m_eState != RTSS_ESTABLISHED && m_eState != RTSS_CLOSED && m_eState != RTSS_CLOSE_WAIT) {
		return false;
	}

	if (m_nReadableBytes == 0) {
		if (m_eState == RTSS_ESTABLISHED) {
			return false;
		}
		else if (m_eState == RTSS_CLOSED || m_eState == RTSS_CLOSE_WAIT) {
			return true;
		}
		else {
			RTASSERT(false);
			return false;
		}
	}
	else {
		return true;
	}
}

bool UTPSocket::IsWritable()
{
	if (m_eState != RTSS_ESTABLISHED) {
		return false;
	}

	if (GetAllowWriteBytes() - m_nNotAckedDataBytes > 0)
		return true;
	else
		return false;
}

bool UTPSocket::IsConnected()
{
	return m_eState == RTSS_ESTABLISHED;
}

int UTPSocket::GetError()
{
	return m_nError;
}


void UTPSocket::OnTick()
{
	if (m_eState == RTSS_CLOSED) {
		return;
	}
    
	int64_t nCurStartTime = m_ptrClocker->GetMicroSecond();
	//LOG_DEBUG(logger, "on tick, time: {}", nCurTime);

	if (nCurStartTime - m_nLastReceivedTime > m_nConnTimeoutTime) {
		LOG_DEBUG(logger, "{} long time no receive packet, connection aborted", (void*)this);
		ChangeToState(RTSS_CLOSED);
		ClearConnection();
		m_nError = RTTP_ECONNABORTED;
		if (m_pfCallBack)
			m_pfCallBack((RTSOCKET)this, RTTP_EVENT_ERROR);
		return;
	}

	if (m_nError != 0) {
		LOG_DEBUG(logger, "{} connection error:{}", (void*)this, m_nError);
		ChangeToState(RTSS_CLOSED);
		ClearConnection();
		if (m_pfCallBack)
			m_pfCallBack((RTSOCKET)this, RTTP_EVENT_ERROR);
		return;
	}

	if (m_eState == RTSS_CLOSE_WAIT) {
		if (nCurStartTime - m_nStateChangeTime > 5 * 1000 * 1000) {
			LOG_DEBUG(logger, "{} RTSS_CLOSE_WAIT timeout, connection closed", (void*)this);
			ClearConnection();
			ChangeToState(RTSS_CLOSED);
			return;
		}
	}

	//resend command packet
	for (uint32_t i = 0; i < m_deqNotAckedCmdPacket.size(); ++i) {
		std::shared_ptr<PacketCS> pkt = m_deqNotAckedCmdPacket[i];
		int64_t nTimeoutTime = m_ptrRoundTripMeter->GetTimeoutValue();
		int64_t nElapseTime = nCurStartTime - pkt->send_time;
		if (nElapseTime > nTimeoutTime || nElapseTime < 0) {
			m_ptrRoundTripMeter->OnPacketLost();
			if (m_eState == RTSS_SYN_SENT && pkt->resend_times > MAX_SYN_RESEND_TIMES || m_eState == RTSS_CLOSING && pkt->resend_times > MAX_CLOSE_RESEND_TIMES) {
				ChangeToState(RTSS_ERROR);
				m_deqNotAckedCmdPacket.clear();
				m_nError = RTTP_ETIMEDOUT;
				if (m_pfCallBack)
					m_pfCallBack((RTSOCKET)this, RTTP_EVENT_ERROR);
				return;
			}
			else {
				ResendPacket(*pkt);
			}
		}
	}



	uint32_t nPktNum = m_deqNotAckedDataPacket.size();
	uint32_t i = 0;

	bool bFoundLost = false;

	int64_t timeout = m_ptrRoundTripMeter->GetTimeoutValue();
	int64_t nCurRTT = m_ptrRoundTripMeter->GetRTT();
	LOG_DEBUG(logger, "{} current time: {}, m_deqNotAckedDataPacket size: {}, current timeout value:{}, rtt:{}", (void*)this, nCurStartTime, nPktNum, timeout, nCurRTT);

	for (; i < nPktNum; ++i) {
		std::shared_ptr<PacketCS> pkt = m_deqNotAckedDataPacket[i];
		int64_t elapse = nCurStartTime - pkt->send_time;

		if (pkt->ack_time ==0 && (elapse > timeout || elapse < 0)) {
			bFoundLost = true;

			LOG_DEBUG(logger, "{} current timeoutvalue: {}, elapse time: {}", (void*)this, timeout, elapse);
			LOG_DEBUG(logger, "{} found packet {} lost when tick, resend time: {}, current state: {}", (void*)this, pkt->pkt_seq, pkt->resend_times, StateDesc(m_eState));
			if (pkt->resend_times == 0) {
				++m_nFoundLostPktNum;
				LOG_INFO(logger, "{} found packet lost, timeout value:{}, current state: {}", (void*)this, timeout, StateDesc(m_eState));
			}

			ResendPacket(*pkt);

		}
	}

	/*
	uint32_t nPktNum = m_deqSendTimeOrderedDataPacket.size();
	uint32_t i = 0;
	
	bool bFoundLost = false;

	LOG_DEBUG(logger, "{} current time: {}, m_deqSendTimeOrderedDataPacket size: {}", (void*)this, nCurStartTime, nPktNum);

	int64_t timeout = m_ptrRoundTripMeter->GetTimeoutValue();
	while (m_deqSendTimeOrderedDataPacket.size() > 0 && i++ < nPktNum) {
		std::shared_ptr<PacketCS> pkt = m_deqSendTimeOrderedDataPacket[0];
		int64_t elapse = nCurStartTime - pkt->send_time;
		
		if (pkt->ack_time != 0) {
			m_deqSendTimeOrderedDataPacket.pop_front();
			continue;
		}

		if (elapse > timeout || elapse < 0) {
			bFoundLost = true;

			LOG_DEBUG(logger, "{} current timeoutvalue: {}, elapse time: {}", (void*)this, timeout, elapse);
			LOG_DEBUG(logger, "{} found packet lost when tick, resend time: {}, current state: {}", (void*)this, pkt->resend_times, StateDesc(m_eState));
			if (pkt->resend_times == 0) {
				++m_nFoundLostPktNum;
				m_ptrPacketLostCounter->OnPacketLost(nCurStartTime);
				LOG_INFO(logger, "{} found packet lost, timeout value:{}, current state: {}", (void*)this, timeout, StateDesc(m_eState));
			}
			
			m_deqSendTimeOrderedDataPacket.pop_front();
			m_deqSendTimeOrderedDataPacket.push_back(pkt);
			ResendPacket(*pkt);

		}
		else {
			//for test
			LOG_INFO(logger, "{} left not timeout packet:", (void*)this);
			for (size_t i = 0; i < m_deqSendTimeOrderedDataPacket.size(); ++i) {
				LOG_INFO(logger, "{} {}", (void*)this, m_deqSendTimeOrderedDataPacket[i]->Desc());
			}

			break;
		}
	}

	*/

	if (bFoundLost) {
		m_ptrCongestionController->OnPacketLost(nCurStartTime);
		m_ptrRoundTripMeter->OnPacketLost();
	}

	if (nCurStartTime - m_nLastSendAck > GetAckInterval() && (m_eState == RTSS_ESTABLISHED || m_eState == RTSS_CLOSING)) {
		SendState();
	}

    m_nTickTakeTime = m_ptrClocker->GetMicroSecond() - nCurStartTime;
}

int UTPSocket::OnPacket(const char* buffer, int len, const char *from, int from_len)
{
	const PacketHead * header = (const PacketHead *)buffer;

	if (from != NULL && from_len > 0)
		m_strRemoteAddr.assign(from, from_len);

	m_nLastReceivedTime = m_ptrClocker->GetMicroSecond();

	/////////////////////////////////////////////////////////////////////////////////////////
	uint32_t nMyTimeLowPart = uint32_t(m_nLastReceivedTime & 0xFFFFFFFF);
	m_nTheirTimestampDiff = nMyTimeLowPart - header->timestamp;

	uint64_t nCurMS = m_ptrClocker->GetMicroSecond() / 1000;
	m_RemoteDelayHistory.AddSample(m_nTheirTimestampDiff, nCurMS);
	LOG_DEBUG(logger, "{} their time stamp diff sample: {}, my time low part:{}, send time stamp:{}", (void*)this, m_RemoteDelayHistory.GetValue(), nMyTimeLowPart, header->timestamp);

	if (header->timestamp_difference != 0) {
		m_nMyTimestampDiff = header->timestamp_difference;

		m_MyDelayHistory.AddSample(m_nMyTimestampDiff, nCurMS);

		m_ptrCongestionController->OnPacketTripTime(m_ptrClocker->GetMicroSecond(), m_MyDelayHistory.GetValue(), m_ptrRoundTripMeter->GetRTT(), m_nNotAckedDataBytes);
		m_ptrRoundTripMeter->OnPacketAcked();

		LOG_DEBUG(logger, "{} my time stamp diff sample: {}, congestion control wnd: {}", (void*)this, m_MyDelayHistory.GetValue(), m_ptrCongestionController->GetCongestionWnd());
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////

	switch (header->GetType()) {
	case RTC_DATA:
		//std::cout << "data packet" << endl;
		OnData(header, len);
		break;
	case RTC_STATE:
		//std::cout << "ack packet" << endl;
		LOG_DEBUG(logger, "{} received state {}", (void*)this, PacketDesc(header));
		OnState(header, len);
		break;
	case RTC_SYN:
		OnSyn(header, len);
		break;
	case RTC_FIN:
		OnClose(header, len);
		break;
	case RTC_RESET:
		OnReset(header, len);
		break;
	default:
		return -1;
	}

	if (m_bWaitConnect && m_eState == RTSS_ESTABLISHED) {
		m_bWaitConnect = false;
		if (m_pfCallBack)
			m_pfCallBack((RTSOCKET)this, RTTP_EVENT_CONNECT);
	}

	if (m_bWaitRead && IsReadable()) {
		m_bWaitRead = false;
		if (m_pfCallBack)
			m_pfCallBack((RTSOCKET)this, RTTP_EVENT_READ);
	}

	if (m_bWaitWrite && m_eState == RTSS_ESTABLISHED ) {
		if (IsWritable()) {
			m_bWaitWrite = false;
			if (m_pfCallBack)
				m_pfCallBack((RTSOCKET)this, RTTP_EVENT_WRITE);
		}
	}

	return 0;
}


int UTPSocket::DoSendData(char* buffer, int len, bool withack)
{
	HeaderToBigEndian((PacketHead*)buffer);
	
	if (withack) {
		m_nLastSendAck = m_ptrClocker->GetMicroSecond();
	}

	if (m_pfSendProc) {
		m_pfSendProc((RTSOCKET)this, buffer, len, m_strRemoteAddr.c_str(), m_strRemoteAddr.size());
	}
	else {
		RTASSERT(false);
	}
	return 0;
}

int UTPSocket::SendSyn(bool ack)
{
	std::shared_ptr<PacketCS> pcs(new PacketCS());

	int nBuffSize = sizeof(PacketHead);
	RTASSERT(pcs->buffer == NULL);

	pcs->buffer = new char[nBuffSize];
	pcs->len = nBuffSize;
	pcs->pos = 0;
	pcs->resend_times = 0;
	pcs->send_time = m_ptrClocker->GetMicroSecond();

	PacketHead *pHead = (PacketHead*)pcs->buffer;

	FillPacketHead(pHead, RTC_SYN, 0, 0);

	pcs->pkt_cmd = pHead->GetType();
	pcs->pkt_head_len = sizeof(PacketHead);
	pcs->pkt_data_bytes = 0;
	pcs->pkt_bitmap_bytes = 0;
	pcs->pkt_seq = pHead->pkt_seq;
	
	
	if (!ack)
		m_deqNotAckedCmdPacket.push_back(pcs);

	LOG_DEBUG(logger, "{} send syn {}", (void*)this, PacketDesc(pHead));

	DoSendData(pcs->buffer, nBuffSize, ack);

	m_nLocalSendPktSeq += 1;

	return 0;
}

int UTPSocket::SendReset()
{
	const int nBuffSize = 1500;
	char buff[nBuffSize];

	char *pBuffer = buff;

	PacketHead *pHead = (PacketHead*)pBuffer;

	FillPacketHead(pHead, RTC_RESET, 0, 0);

	LOG_DEBUG(logger, "{} send reset {}", (void*)this, PacketDesc(pHead));

	DoSendData(pBuffer, nBuffSize, true);

	m_nLocalSendPktSeq += 1;

	return 0;
}

int UTPSocket::SendData(const char * buffer, int len, int flag)
{
	int nBitmapBytes = GetBitmapBytes(m_nLocalExpectPktSeq, m_mapReceivedPacket);
	
	int nBuffSize = sizeof(PacketHead) + GetBitmapExtensionBytes(nBitmapBytes) + len;
	char *pBuffer = new char[nBuffSize];

	PacketHead *pHead = (PacketHead*)pBuffer;

	int nHeadLen = FillPacketHead(pHead, RTC_DATA, len, nBitmapBytes);

	memcpy(pBuffer + nHeadLen, buffer, len);

	LOG_DEBUG(logger, "{} send data {}", (void*)this, PacketDesc(pHead));

	++m_nTotalSendTimes;

	std::shared_ptr<PacketCS> pkt(new PacketCS());
	pkt->buffer = pBuffer;
	pkt->len = nBuffSize;
	pkt->pos = 0;
	pkt->pkt_cmd = RTC_DATA;
	pkt->pkt_seq = pHead->pkt_seq;
	
	pkt->pkt_data_bytes = len;
	pkt->pkt_head_len = nHeadLen;
	pkt->pkt_bitmap_bytes = nBitmapBytes;

	pkt->send_time = m_ptrClocker->GetMicroSecond();

	DoSendData(pBuffer, nBuffSize, true);

	m_nLocalSendPktSeq += 1;
	m_nLocalSendBytesSeq += len;

	m_deqNotAckedDataPacket.push_back(pkt);
	//m_deqSendTimeOrderedDataPacket.push_back(pkt);
	++m_nTotalPktNum;

	m_nNotAckedDataBytes += len;

	return 0;
}

int UTPSocket::SendState()
{
	int nBitmapBytes = GetBitmapBytes(m_nLocalExpectPktSeq, m_mapReceivedPacket);

	int nBuffSize = sizeof(PacketHead) + GetBitmapExtensionBytes(nBitmapBytes);

	char buff[1500];

	char *pBuffer = buff;

	PacketHead *pHead = (PacketHead*)pBuffer;

	FillPacketHead(pHead, RTC_STATE, 0, nBitmapBytes);

	LOG_DEBUG(logger, "{} send state {}", (void*)this, PacketDesc(pHead));

	
	DoSendData(pBuffer, nBuffSize, true);

	return 0;
}

int UTPSocket::SendClose(bool resp)
{
	std::shared_ptr<PacketCS> pcs(new PacketCS());

	int nBuffSize = sizeof(PacketHead);

	pcs->buffer = new char[nBuffSize];
	pcs->len = nBuffSize;
	pcs->pos = 0;
	pcs->resend_times = 0;
	pcs->send_time = m_ptrClocker->GetMicroSecond();

	PacketHead *pHead = (PacketHead*)pcs->buffer;
	FillPacketHead(pHead, RTC_FIN, 0, 0);

	pcs->pkt_cmd = RTC_FIN;
	pcs->pkt_head_len = sizeof(PacketHead);
	pcs->pkt_data_bytes = 0;
	pcs->pkt_bitmap_bytes = 0;
	pcs->pkt_seq = pHead->pkt_seq;

	if (!resp)
		m_deqNotAckedCmdPacket.push_back(pcs);

	LOG_DEBUG(logger, "{} send close {}", (void*)this, PacketDesc(pHead));

	DoSendData(pcs->buffer, nBuffSize, false);

	return 0;
}

void UTPSocket::OnSyn(const PacketHead *pHeader, int nPktLen)
{
	LOG_DEBUG(logger, "{} received syn {}", (void*)this, PacketDesc(pHeader));
	if (!m_bPassive) {
		SendReset();
	}

	if (m_eState != RTSS_IDLE && m_eState != RTSS_SYN_RECEIVED)
		return;

	if (m_eState != RTSS_SYN_RECEIVED) {
		m_nLocalSendPktSeq = rand() % 65535;
		m_nConnID = pHeader->conn_id;
		m_nLocalExpectPktSeq = pHeader->pkt_seq + 1;

		ChangeToState(RTSS_SYN_RECEIVED);
	}

	SendState();
}


int UTPSocket::OnAck(const PacketHead *pHeader, int nPktLen)
{
	int64_t nStartTime = m_ptrClocker->GetMicroSecond();

	LOG_INFO(logger, "{} ack seq:{}, remote ack seq:{}", (void*)this, pHeader->ack_pkt_seq, (uint16_t)m_nRemoteAckedPktSeq);
	if (m_deqNotAckedDataPacket.size() > 0) {
		LOG_INFO(logger, "{} not acked first pkt seq:{}", (void*)this, m_deqNotAckedDataPacket[0]->pkt_seq);
	}

	if (CircleSeq<uint16_t>(pHeader->ack_pkt_seq) >= m_nRemoteAckedPktSeq) {
		m_nRemoteRecvWnd = pHeader->recv_wnd;
		m_nRemoteAckedPktSeq = pHeader->ack_pkt_seq;
	}
	else {
		LOG_INFO(logger, "{} ack pkt seq < m_nRemoteAckedPktSeq, ignore", (void*)this);
		return -1;
	}

	bool bNotifyWrite = false;
	while (m_deqNotAckedDataPacket.size() > 0) {
		std::shared_ptr<PacketCS> pcs = m_deqNotAckedDataPacket[0];
		int64_t nCurTime = m_ptrClocker->GetMicroSecond();
		if (CircleSeq<uint16_t>(pcs->pkt_seq) <= m_nRemoteAckedPktSeq) {
			if (pcs->ack_time == 0) {
				pcs->ack_time = nCurTime;
				int64_t rtt = pcs->ack_time - pcs->send_time;
				if (pcs->resend_times == 0) {
					m_ptrRoundTripMeter->OnPacketAcked(rtt);
					m_ptrPacketLostCounter->OnPacketAcked(nCurTime);
				}
				else {
					m_ptrRoundTripMeter->OnPacketAcked();
				}
				m_ptrCongestionController->OnPacketAcked(nCurTime, rtt);

				LOG_INFO(logger, "{} ack: rtt: {}, timeout value: {}", (void*)this, rtt, m_ptrRoundTripMeter->GetTimeoutValue());
			}

			bNotifyWrite = true;
			m_nNotAckedDataBytes -= pcs->pkt_data_bytes;
			m_deqNotAckedDataPacket.pop_front();

			LOG_INFO(logger, "{} pkt: {} acked, remove from m_deqNotAckedDataPacket", (void*)this, pcs->pkt_seq);
		}
		else {
			if (CircleSeq<uint16_t>(pcs->pkt_seq) == m_nRemoteAckedPktSeq + 1) {
				pcs->wanted_times++;
				if (pcs->wanted_times == 4 && pcs->resend_times == 0) {
					LOG_INFO(logger, "{} {} packet was wanted 4 times, fast resend it", (void*)this, pcs->pkt_seq);

					ResendPacket(*pcs);
				}
			}
			else {
				RTASSERT(false);
			}
			break;
		}
	}

	uint8_t nCurExtension = pHeader->extension;
	const uint8_t* pStartPos = (const uint8_t*)pHeader + sizeof(PacketHead);
	const uint8_t* pCurPos = pStartPos ;
	while (nCurExtension != 0) {
		
		if (pCurPos + 2 - pStartPos > nPktLen) {
			LOG_INFO(logger, "{} invalid packet with extension", (void*)this);
			return -1;
		}

		uint8_t nNextExtension = *pCurPos++;
		uint8_t nCurExtLen = *pCurPos++;


		if (pCurPos + nCurExtLen - pStartPos > nPktLen) {
			LOG_INFO(logger, "{} invalid packet with extension", (void*)this);
			return -1;
		}

		if (nCurExtension == EXT_SACK) {
			int nBitmapBytes = nCurExtLen;
			const char* pBitmapStart = (const char*)pCurPos;

			LOG_DEBUG(logger, "{} bitmap bytes: {}, bitmap: {}", (void*)this, nBitmapBytes, Bitmap01String(pBitmapStart, nBitmapBytes));

			if (m_deqNotAckedDataPacket.size() > 0) {
				RTASSERT(CircleSeq<uint16_t>(m_deqNotAckedDataPacket[0]->pkt_seq) == CircleSeq<uint16_t>(pHeader->ack_pkt_seq) + 1);
			}

			for (size_t i = 1; i < m_deqNotAckedDataPacket.size(); ++i) {
				std::shared_ptr<PacketCS> pcs = m_deqNotAckedDataPacket[i];
				uint64_t nCurTime = m_ptrClocker->GetMicroSecond();
				int pos = (uint16_t)(CircleSeq<uint16_t>(pcs->pkt_seq) - CircleSeq<uint16_t>(pHeader->ack_pkt_seq) - 2);
				RTASSERT(pos >= 0);
				if (pos < nBitmapBytes * 8) {
					if (BitmapGet(pos, pBitmapStart, nBitmapBytes)) {

						if (pcs->ack_time == 0) {
							pcs->ack_time = nCurTime;

							int64_t rtt = pcs->ack_time - pcs->send_time;
							if (pcs->resend_times == 0) {
								m_ptrRoundTripMeter->OnPacketAcked(rtt);
								m_ptrPacketLostCounter->OnPacketAcked(nCurTime);
							}
							else {
								m_ptrRoundTripMeter->OnPacketAcked();
							}
							m_ptrCongestionController->OnPacketAcked(nCurTime, rtt);

							LOG_INFO(logger, "{} bitmap ack: pkt:{} rtt: {}, sendtime:{}, rsend_times:{} cur_time:{}, timeout value: {}", (void*)this,
								pcs->pkt_seq, rtt, pcs->send_time, pcs->resend_times, nCurTime, m_ptrRoundTripMeter->GetTimeoutValue());
						}
					}
				}
				else {
					break;
				}
			}
		}

		pCurPos += nCurExtLen;
		nCurExtension = nNextExtension;
		
	}

	if (m_eState == RTSS_CLOSING) {
		if (m_deqNotAckedDataPacket.size() == 0 && m_deqNotAckedCmdPacket.size() == 0) {
			SendClose(false);
		}
	}

	m_nAckTakeTime = m_ptrClocker->GetMicroSecond() - nStartTime;

	return pCurPos - pStartPos;
}

void UTPSocket::OnState(const PacketHead *pHeader, int nPktLen)
{
	LOG_DEBUG(logger, "{} on state {}", (void*)this, PacketDesc(pHeader));

	if (m_eState == RTSS_SYN_SENT) {
		if (CircleSeq<uint16_t>(pHeader->ack_pkt_seq) == m_nLocalSendPktSeq - 1) {
			m_nLocalExpectPktSeq = CircleSeq<uint16_t>(pHeader->pkt_seq);
			m_deqNotAckedCmdPacket.clear();
			ChangeToState(RTSS_ESTABLISHED);
		}
		else {
			return;
		}
	}

	if (!IsPacketValid(pHeader)) {
		LOG_DEBUG(logger, "{} state not in recv window", (void*)this);
		return;
	}

	OnAck(pHeader, nPktLen);
}

int UTPSocket::ResendPacket(PacketCS &pkt)
{

	if (pkt.pkt_head_len + pkt.pkt_data_bytes != pkt.len) {
		RTASSERT(false);
	}

	int nBitmapBytes = GetBitmapBytes(m_nLocalExpectPktSeq, m_mapReceivedPacket);

	PacketHead *pHeader = (PacketHead*)pkt.buffer;

	char *pBuffer = NULL;
	int nHeadLen = pkt.pkt_head_len;
	uint32_t nPktSeq = pkt.pkt_seq;
	uint8_t nCmd = pkt.pkt_cmd;

	RTASSERT(pkt.pkt_data_bytes >= 0);
	RTASSERT(pkt.pkt_head_len > 0);

	int nTotalSize = sizeof(PacketHead) + GetBitmapExtensionBytes(nBitmapBytes) + pkt.pkt_data_bytes;
	if (nTotalSize != pkt.len) {
		
		pBuffer = new char[nTotalSize];
		nHeadLen = sizeof(PacketHead) + GetBitmapExtensionBytes(nBitmapBytes);
		memcpy(pBuffer + nHeadLen, pkt.buffer + pkt.pkt_head_len, pkt.pkt_data_bytes);
		pHeader = (PacketHead*)pBuffer;

		delete[] pkt.buffer;
		pkt.buffer = pBuffer;
		pkt.pkt_head_len = nHeadLen;
		pkt.len = nTotalSize;
	}
	else {
		pBuffer = pkt.buffer;
	}

	
	pHeader->SetVersion(UTP_VER);
	pHeader->SetType(nCmd);
	
	if (nCmd == RTC_SYN)
		pHeader->conn_id = m_nConnID;
	else {
		if (m_bPassive) {
			pHeader->conn_id = m_nConnID;
		}
		else {
			pHeader->conn_id = m_nConnID + 1;
		}
	}

	pHeader->pkt_seq = nPktSeq;
	pHeader->recv_wnd = GetLeftRecvWndBytes();
	pHeader->ack_pkt_seq = (uint16_t)(m_nLocalExpectPktSeq-1);
	
	pHeader->timestamp = (uint32_t)(GetMicroSecondsSinceEpoch() & 0xFFFFFFFF);
	pHeader->timestamp_difference = m_nTheirTimestampDiff;

	m_nSendSeq += 1;

	if (nBitmapBytes > 0) {
		GenerateAckBitfield(m_nLocalExpectPktSeq, m_mapReceivedPacket, pBuffer + nHeadLen- nBitmapBytes, nBitmapBytes);
		pHeader->extension = 1;

		PacketHeadAck* pHeadWithAck = (PacketHeadAck*)pHeader;
		pHeadWithAck->ext_next = 0;
		pHeadWithAck->ext_len = nBitmapBytes;
	}
	else {
		pHeader->extension = 0;
	}

	pkt.send_time = m_ptrClocker->GetMicroSecond();
	++pkt.resend_times;

	LOG_DEBUG(logger, "{} resend packet {}", (void*)this, PacketDesc(pHeader));

	LOG_DEBUG(logger, "{} resend times: {}", (void*)this, pkt.resend_times);

	LOG_INFO(logger, "{} resend pkt {}, send time: {}", (void*)this, nPktSeq, pkt.send_time);
	++m_nTotalSendTimes;
	
	if (pkt.pkt_head_len + pkt.pkt_data_bytes != pkt.len) {
		//cout << "invalid pkt info" << endl;
		RTASSERT(false);
	}

	DoSendData(pBuffer, nTotalSize, true);

	return 0;
}

bool UTPSocket::IsPacketValid(const PacketHead* pHeader)
{
	if (CircleSeq<uint16_t>(pHeader->pkt_seq) < m_nLocalExpectPktSeq) {
		LOG_DEBUG(logger, "!!{} packet not in window: pkt seq: {}, local expect pkt seq: {}", (void*)this, pHeader->pkt_seq, (uint16_t)m_nLocalExpectPktSeq);
		return false;
	}

	if (CircleSeq<uint16_t>(pHeader->ack_pkt_seq) > m_nLocalSendPktSeq) {
		LOG_DEBUG(logger, "!!{} packet not in window: ack pkt seq: {}, local send pkt seq: {}", (void*)this, pHeader->ack_pkt_seq, (uint16_t)m_nLocalSendPktSeq);
		return false;

	}

	return true;
}

int UTPSocket::GetAllowWriteBytes()
{
	uint32_t nCongestionAllow = m_ptrCongestionController->GetCongestionWnd();

	if (nCongestionAllow > m_nNotAckedDataBytes) {
		nCongestionAllow -= m_nNotAckedDataBytes;
	}
	else {
		nCongestionAllow = 0;
	}

	int bytes = (std::min)(GetLeftSendWndBytes(), nCongestionAllow);

	return bytes;
}

uint32_t UTPSocket::GetAckInterval()
{
	return m_nAckInterval;
}

uint32_t UTPSocket::GetLeftSendWndBytes()
{
	if (m_nRemoteRecvWnd > m_nNotAckedDataBytes) {
		return m_nRemoteRecvWnd - m_nNotAckedDataBytes;
	}
	else {
		return 0;
	}

}

uint32_t UTPSocket::GetLeftRecvWndBytes()
{
	//uint32_t nTotalBufferedBytes = m_nReadableBytes + m_nNotReadableBytes;

	uint32_t nTotalBufferedBytes = m_nReadableBytes;
	if (m_nLocalRecvWnd >= nTotalBufferedBytes)
		return m_nLocalRecvWnd - nTotalBufferedBytes;
	else
		return 0;
}


bool UTPSocket::SaveReceivedData(std::shared_ptr<PacketCS> pkt, CircleSeq<uint16_t> pkt_seq, int len)
{
	
	RTASSERT(len == pkt->len);

	if (pkt_seq == m_nLocalExpectPktSeq) {

		LOG_DEBUG(logger, "{}data packet seq equals to next expect packet seq, buffered packet num:{}", (void*)this, m_mapReceivedPacket.size());

		m_nLocalExpectPktSeq += 1;
		m_nReadableBytes += len;

		m_deqReady4ReadPacket.push_back(pkt);

		std::map<CircleSeq<uint16_t>, std::shared_ptr<PacketCS>>::iterator iter;
		for (iter = m_mapReceivedPacket.begin(); iter != m_mapReceivedPacket.end(); ) {
			if (iter->first == m_nLocalExpectPktSeq) {
				m_nLocalExpectPktSeq += 1;
				
				m_nReadableBytes += iter->second->len;

				RTASSERT(m_nNotReadableBytes >= iter->second->len);
				m_nNotReadableBytes -= iter->second->len;

				LOG_DEBUG(logger, "{}, -{} bytes, not readable bytes:{}", (void*)this, iter->second->len, m_nNotReadableBytes);

				m_deqReady4ReadPacket.push_back(iter->second);
				iter = m_mapReceivedPacket.erase(iter);
			}
			else if (iter->first < m_nLocalExpectPktSeq) {
				RTASSERT(false);//impossible
			}
			else {
				break;
			}
		}

		/*if (m_mapReceivedPacket.size() == 0) {
			RTASSERT(m_nNotReadableBytes == 0);
		}
		else {
			RTASSERT(m_nNotReadableBytes > 0);
		}*/

		LOG_DEBUG(logger, "{} left buffered packet num:{}", (void*)this, m_mapReceivedPacket.size());

		
		/*int64_t nSumNotReadableByts = 0;
		for (auto iter = m_mapReceivedPacket.begin(); iter != m_mapReceivedPacket.end(); ++iter) {
			nSumNotReadableByts += iter->second->len;
		}

		RTASSERT(nSumNotReadableByts == m_nNotReadableBytes);*/

		return true;
	}
	else {

		if (m_mapReceivedPacket.size() == 0) {
			RTASSERT(m_nNotReadableBytes == 0);
		}
		else {
			RTASSERT(m_nNotReadableBytes > 0);
		}

		if (m_mapReceivedPacket.find(pkt_seq) == m_mapReceivedPacket.end()) {
			m_nNotReadableBytes += len;
			m_mapReceivedPacket[pkt_seq] = pkt;
		}

		LOG_DEBUG(logger, "{} !data packet seq not equals next expect packet seq, save in buffer, buffered packet num:{}, +{} bytes, not readable bytes: {}", 
			(void*)this, m_mapReceivedPacket.size(), len, m_nNotReadableBytes);

		
		/*int64_t nSumNotReadableByts = 0;
		for (auto iter = m_mapReceivedPacket.begin(); iter != m_mapReceivedPacket.end(); ++iter) {
			nSumNotReadableByts += iter->second->len;
		}

		RTASSERT(nSumNotReadableByts == m_nNotReadableBytes);*/

		return false;
	}
}

void UTPSocket::OnData(const PacketHead *pHeader, int nPktLen)
{
	LOG_DEBUG(logger, "{} received data {}", (void*)this, PacketDesc(pHeader));

	if (m_eState == RTSS_SYN_RECEIVED ) {
		if (pHeader->ack_pkt_seq == (m_nLocalSendPktSeq - 1) && pHeader->pkt_seq == (uint16_t)m_nLocalExpectPktSeq) {
			m_nRemoteRecvWnd = pHeader->recv_wnd;
			m_nRemoteAckedPktSeq = pHeader->ack_pkt_seq;
			ChangeToState(RTSS_ESTABLISHED);
		}
		else {
			LOG_DEBUG(logger, "{} RTSS_SYN_RECEIVED state received data, but ack seq wrong", (void*)this);
			return;
		}
	}

	if (!IsPacketValid(pHeader)) {
        LOG_DEBUG(logger, "{} received data not in recv window", (void*)this);
		return;
	}

	if (m_eState != RTSS_ESTABLISHED)
		return;

	LOG_DEBUG(logger, "{} next expected pkt seq: {}, received pkt seq:{}", (void*)this, (uint16_t)m_nLocalExpectPktSeq, pHeader->pkt_seq);

	int nConsumed = OnAck(pHeader, nPktLen);
	if (nConsumed < 0) {
		return;
	}

	const char* body = (const char*)pHeader + sizeof(PacketHead) + nConsumed;
	int len = nPktLen - sizeof(PacketHead) - nConsumed;
	RTASSERT(len > 0);
	LOG_DEBUG(logger, "{} data packet, data bytes:{}", (void*)this, len);

	std::shared_ptr<PacketCS> pkt(new PacketCS());
	pkt->len = len;
	pkt->buffer = new char[len];
	memcpy(pkt->buffer, body, len);
	pkt->pos = 0;
	pkt->pkt_seq = pHeader->pkt_seq;
	pkt->pkt_head_len = 0;
	pkt->pkt_bitmap_bytes = 0;
	pkt->pkt_data_bytes = len;

	bool bWantedSeq = SaveReceivedData(pkt, pHeader->pkt_seq, len);

	if (m_bFastAck || !bWantedSeq) {
		SendState();
	}
}

void UTPSocket::OnClose(const PacketHead *pHeader, int nPktLen)
{
	LOG_DEBUG(logger, "{} received close {}", (void*)this, PacketDesc(pHeader));

	if (!IsPacketValid(pHeader)) {
		return;
	}


	if (m_eState == RTSS_CLOSING) {
		ClearConnection();
		ChangeToState(RTSS_CLOSED);
	}
	else {
		if (m_eState != RTSS_CLOSE_WAIT) {
			ChangeToState(RTSS_CLOSE_WAIT);//remote close connection
			ClearConnection();
		}
		SendClose(true);
	}
}

void UTPSocket::OnReset(const PacketHead *pHeader, int nPktLen)
{
	LOG_DEBUG(logger, "{} received reset {}", (void*)this, PacketDesc(pHeader));

	if (CircleSeq<uint16_t>(pHeader->ack_pkt_seq) > m_nLocalSendPktSeq) {
		return;
	}

	if (m_eState != RTSS_CLOSED) {
		m_deqNotAckedCmdPacket.clear();
		m_deqNotAckedDataPacket.clear();

		ChangeToState(RTSS_ERROR);

		m_nError = RTTP_ECONNRESET;
	}
}


int UTPSocket::SetSockOpt(int optname, void *optval, int optlen)
{
	if (optlen < 4) {
		return -1;
	}
	if (optname == RTSO_MTU) {
		int32_t mtu = *(int32_t*)optval;
		if (mtu > 1500 - 20 - 20 - 8 - 100 - sizeof(PacketHead))
			return -1;
		m_nMtu = mtu;
	}
	else if (optname == RTSO_FEC) {
		m_bEnableFec = *(int32_t*)optval == 1 ? true : false;
	}
	else if (optname == RTSO_FAST_ACK) {
		m_bFastAck = *(int32_t*)optval == 1 ? true : false;
	}
	else if (optname == RTSO_RCVBUF) {
		m_nLocalRecvWnd = *(int32_t*)optval;
	}
	else if (optname == RTSO_MODE) {
		int32_t mode = *(int32_t*)optval;
		if (mode == RTSM_LOW_LATENCY) {
			m_ptrCongestionController.reset(new LedbatCongestionController(m_nMtu, m_nMtu, 100*1000));
			m_ptrRoundTripMeter->SetBeta(1.5);
			m_bEnableFec = true;
			m_bFastAck = true;
		}
		else if (mode == 1) {
			m_ptrCongestionController.reset(new LedbatCongestionController(m_nMtu, m_nMtu, 100 * 1000));
			m_ptrRoundTripMeter->SetBeta(2);
			m_bFastAck = true;
			m_bEnableFec = false;
		}
		else {
			return -1;
		}
	}
	else {
		return -1;
	}
	return 0;
}

int UTPSocket::GetSockOpt(int optname, void *optval, int optlen)
{
	if (optlen < 4)
		return RTTP_EINSUFFICIENT_BUFFER;

	if (optname == RTSO_MTU) {
		*(int32_t *)optval = m_nMtu;
		return 4;
	}
	else if(optname == RTSO_FEC) {
		*(int32_t *)optval = m_bEnableFec ? 1 : 0;
		return 4;
	}
	else if(optname == RTSO_FAST_ACK) {
		*(int32_t *)optval = m_bFastAck ? 1 : 0;
		return 4;
	}
	else if(optname == RTSO_RCVBUF) {
		*(int32_t *)optval = m_nLocalRecvWnd;
		return 4;
	}
	else if(optname == RTSO_RTT) {
		if (optlen < 8)
			return RTTP_EINSUFFICIENT_BUFFER;

		*(int64_t *)optval = m_ptrRoundTripMeter->GetRTT();
		return 8;
	}
	else if(optname == RTSO_LOST_RATE) {
		if (m_nTotalPktNum == 0) {
			*(int32_t*)optval = 0;
		}
		else {
			*(int32_t*)optval = 100*m_nFoundLostPktNum / m_nTotalPktNum;
		}
		return 4;
	}
	else if (optname == RTSO_RECENT_LOST_RATE) {
		*(int32_t*)optval = m_ptrPacketLostCounter->GetLostPercent();
		return 4;
	}
	else {
		return -1;
	}
}

int UTPSocket::FillPacketHead(PacketHead* pHead, RTCommand cmd, int nDataBytes, int nBitmapBytes)
{
	int nHeadLen = sizeof(PacketHead) + GetBitmapExtensionBytes(nBitmapBytes);

	pHead->SetVersion(UTP_VER);
	pHead->SetType(cmd);

	if (cmd == RTC_SYN)
		pHead->conn_id = m_nConnID;
	else {
		if (m_bPassive) {
			pHead->conn_id = m_nConnID;
		}
		else {
			pHead->conn_id = m_nConnID + 1;
		}
	}

	pHead->extension = 0;
	pHead->pkt_seq = (uint16_t)m_nLocalSendPktSeq;


	pHead->recv_wnd = GetLeftRecvWndBytes();
	pHead->ack_pkt_seq = (uint16_t)(m_nLocalExpectPktSeq-1);
	pHead->timestamp = (uint32_t)(GetMicroSecondsSinceEpoch() & 0xFFFFFFFF);
	pHead->timestamp_difference = m_nTheirTimestampDiff;
	/////////////////////////////////////////////////////////////

	m_nSendSeq += 1;

	if (nBitmapBytes > 0) {
		PacketHeadAck* pHeadWithAck = (PacketHeadAck*)pHead;
		pHead->extension = 1;
		pHeadWithAck->ext_next = 0;
		pHeadWithAck->ext_len = nBitmapBytes;
		char* pBuffer = (char*)pHead;

		GenerateAckBitfield(m_nLocalExpectPktSeq, m_mapReceivedPacket, pBuffer + nHeadLen - nBitmapBytes, nBitmapBytes);
	}

	return nHeadLen;
}

std::string UTPSocket::GetInternalState()
{
	std::ostringstream oss;
	oss << "{";
	oss << "\"rtt\":" << m_ptrRoundTripMeter->GetRTT();
	oss << ",\"tov\":" << m_ptrRoundTripMeter->GetTimeoutValue();
	oss << ",\"std\":" << "\""<<StateDesc(m_eState) << "\"";
	oss << ",\"lrw\":" << m_nLocalRecvWnd;
	oss << ",\"rrw\":" << m_nRemoteRecvWnd;
	oss << ",\"lsw\":" << GetLeftSendWndBytes();
	oss << ",\"crw\":" << GetLeftRecvWndBytes();
	oss << ",\"ccw\":" << m_ptrCongestionController->GetCongestionWnd();
	oss << ",\"plr\":" << (m_nTotalPktNum == 0 ? 0 :100 * m_nFoundLostPktNum / m_nTotalPktNum);
	oss << ",\"rlr\":" << m_ptrPacketLostCounter->GetLostPercent();
    oss << ",\"ttt\":" << m_nTickTakeTime;
    oss << ",\"att\":" << m_nAckTakeTime;
    oss << ",\"4tt\":" << s_nTotalTickTakeTime;
	oss << ",\"sqs\":" << m_deqNotAckedDataPacket.size();
	oss << ",\"rqs\":" << m_mapReceivedPacket.size();
	
	oss << ",\"wrb\":" << m_nReadableBytes;
	oss << ",\"mdh\":" << m_MyDelayHistory.GetValue();
	oss << ",\"rdh\":" << m_RemoteDelayHistory.GetValue();
	oss << ",\"rtd\":" << m_nTheirTimestampDiff;
	oss << ",\"mtd\":" << m_nMyTimestampDiff;
	oss << ",\"err\":" << m_nError;
	oss << "}";

	return oss.str();
}

void UTPSocket::ClearConnection()
{
	m_deqNotAckedCmdPacket.clear();
	m_deqNotAckedDataPacket.clear();


}

void UTPSocket::SetUserData(void* userdata)
{ 
	m_pUserdata = userdata; 
}

void* UTPSocket::GetUserData()
{ 
	return m_pUserdata; 
}

}
