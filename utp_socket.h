#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <sstream>
#include <set>
#include "congestion_control.h"
#include "round_trip_meter.h"
#include "utp_socket_c.h"
#include "trip_time_sample.h"
#include "utp_common.h"

#ifdef _MSC_VER
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif //  _MSC_

namespace rtttech_utp
{

	enum RTSocketState { RTSS_IDLE, RTSS_SYN_SENT, RTSS_SYN_RECEIVED, RTSS_ESTABLISHED, RTSS_CLOSING, RTSS_CLOSE_WAIT, RTSS_CLOSED, RTSS_ERROR };

	//enum RTCommand { RTC_SYN, RTC_SYN_ACK, RTC_DATA, RTC_ACK, RTC_CLOSE, RTC_RESET, RTC_FEC };

	enum FECType { FECT_XOR };

	enum RTCommand {
		RTC_DATA = 0,		// Data packet.
		RTC_FIN = 1,			// Finalize the connection. This is the last packet.
		RTC_STATE = 2,		// State packet. Used to transmit an ACK with no data.
		RTC_RESET = 3,		// Terminate connection forcefully.
		RTC_SYN = 4,			// Connect SYN
		RTC_NUM_STATES,		// used for bounds checking
	};

	enum {
		EXT_SACK = 1
	};

	const uint8_t UTP_VER = 1;

#if (defined(__SVR4) && defined(__sun))
#pragma pack(1)
#else
#pragma pack(push,1)
#endif
	/*
	uTP header from BEP 29
	0       4       8               16              24              32
	+-------+-------+---------------+---------------+---------------+
	| type  | ver   | extension     | connection_id                 |
	+-------+-------+---------------+---------------+---------------+
	| timestamp_microseconds                                        |
	+---------------+---------------+---------------+---------------+
	| timestamp_difference_microseconds                             |
	+---------------+---------------+---------------+---------------+
	| wnd_size                                                      |
	+---------------+---------------+---------------+---------------+
	| seq_nr                        | ack_nr                        |
	+---------------+---------------+---------------+---------------+
*/

	struct UTPHeader
	{
		std::uint8_t type_ver;
		std::uint8_t extension;
		std::uint16_t conn_id;
		std::uint32_t timestamp;
		std::uint32_t timestamp_difference;
		std::uint32_t recv_wnd;
		std::uint16_t pkt_seq;
		std::uint16_t ack_pkt_seq;

		int GetType() const { return type_ver >> 4; }
		void SetType(uint8_t t) { type_ver = (type_ver & 0xf) | (t << 4); }

		int GetVersion() const { return type_ver & 0xf; }
		void SetVersion(uint8_t v) { type_ver = (type_ver & 0xf0) | (v & 0xf); }
	};

	typedef UTPHeader PacketHead;

	struct PacketHeadAck {
		PacketHead pf;
		std::uint8_t ext_next;
		std::uint8_t ext_len;
		std::uint8_t acks[4];
	};


#if (defined(__SVR4) && defined(__sun))
#pragma pack(0)
#else
#pragma pack(pop)
#endif

	void HeaderToBigEndian(PacketHead* pHead);

	struct PacketCS
	{
		PacketCS() : buffer(NULL), len(0), pos(0), send_time(0), resend_times(0), ack_time(0),
			fec_sent(false), pkt_data_bytes(0), pkt_seq(0), wanted_times(0) {}
		~PacketCS() { if (buffer) { delete[] buffer; buffer = NULL; } }

		char *buffer;
		int32_t len;
		int32_t pos;
		int64_t send_time;
		int64_t ack_time;
		int32_t resend_times;
		int32_t wanted_times;
		uint16_t pkt_seq;
		int32_t pkt_data_bytes;
		int32_t pkt_head_len;
		int32_t pkt_bitmap_bytes;
		uint8_t pkt_cmd;
		bool	fec_sent;

		std::string Desc() const
		{
			std::ostringstream oss;
			oss << "pkt_seq:" << pkt_seq;
			oss << "len:" << len;
			oss << "send_time:" << send_time;
			oss << "ack_time:" << ack_time;
			oss << "resend_times:" << resend_times;
			oss << "wanted_times:" << wanted_times;
			
			return oss.str();
		}
	};

	class UTPSocket
	{
	public:
		UTPSocket(socket_event_callback *cb, send_data_callback *pfsend, UTPClock* clock, bool passive = false);
		virtual ~UTPSocket();

		int Connect(const char *to, int tolen);
		int Recv(char * buffer, int len, int flag);
		int Send(const char * buffer, int len, int flag);
		void Close();

		void OnTick();
		int OnPacket(const char* buffer, int len, const char *from, int from_len);

		inline RTSocketState State() const { return m_eState; }

		uint16_t GetConnID() const { return m_nConnID; }
		void SetConnID(uint16_t connid) { m_nConnID = connid; }

		bool IsReadable();
		bool IsWritable();
		bool IsConnected();
		int GetError();

		bool IsPassive() const { return m_bPassive; }

		const std::string& GetRemoteAddr() const { return m_strRemoteAddr; }

		inline bool IsDestroyed() const { return m_bDestroyed && (m_eState == RTSS_CLOSED || m_eState == RTSS_ERROR) ; }

		int SetSockOpt(int optname, void *optval, int optlen);
		int GetSockOpt(int optname, void *optval, int optlen);

		void SetUserData(void* userdata);
		void* GetUserData();

		std::string GetInternalState();
    public:
        static uint32_t s_nTotalTickTakeTime;
	private:
		int FillPacketHead(PacketHead* pHeader, RTCommand cmd, int nDataBytes, int nBitmapBytes);

		void ChangeToState(RTSocketState s);

		int DoSendData(char* buffer, int len, bool withack);

		int SendSyn(bool ack = false);
		int SendData(const char * buffer, int len, int flag);
		int SendState();
		int SendClose(bool resp = false);
		int SendReset();

		void ClearConnection();

		void OnSyn(const PacketHead *pHeader, int nPktLen);
		void OnState(const PacketHead *pHeader, int nPktLen);
		void OnData(const PacketHead *pHeader, int nPktLen);
		void OnClose(const PacketHead *pHeader, int nPktLen);
		void OnReset(const PacketHead *pHeader, int nPktLen);

		int OnAck(const PacketHead *pHeader, int nPktLen);

		bool SaveReceivedData(std::shared_ptr<PacketCS> pkt, CircleSeq<uint16_t> pkt_seq, int len);

		bool IsPacketValid(const PacketHead* pHeader);
		uint32_t GetLeftSendWndBytes();
		uint32_t GetLeftRecvWndBytes();

		int ResendPacket(PacketCS &pkt);

		int GetAllowWriteBytes();

		uint32_t GetAckInterval();

	private:
		bool m_bPassive;
		bool m_bDestroyed;
		socket_event_callback *m_pfCallBack;
		send_data_callback *m_pfSendProc;
		void* m_pUserdata;

		int m_nError;
		std::string m_strRemoteAddr;

		RTSocketState m_eState;
		uint64_t m_nStateChangeTime;

		CircleSeq<uint16_t> m_nLocalSendPktSeq, m_nLocalExpectPktSeq, m_nRemoteAckedPktSeq, m_nRemoteExpectBytesSeq;
		CircleSeq<uint16_t> m_nLocalSendBytesSeq, m_nLocalExpectBytesSeq;
		CircleSeq<uint16_t> m_nSendSeq;//

		uint16_t m_nMtu;
		uint32_t m_nRemoteRecvWnd, m_nLocalRecvWnd;
		int32_t m_nReadableBytes;
		int32_t m_nNotReadableBytes;

		int32_t m_nNotAckedDataBytes;
		uint16_t m_nConnID;

		uint64_t m_nLastReceivedTime;
		uint64_t m_nConnTimeoutTime;
		uint64_t m_nLastSendAck;
		uint32_t m_nAckInterval;
		uint64_t m_nLastSendFec;

		uint64_t m_nTotalPktNum;
		uint64_t m_nFoundLostPktNum;
		uint64_t m_nTotalSendTimes;
        
        uint32_t m_nAckTakeTime = 0;
        uint32_t m_nTickTakeTime = 0;

		uint32_t m_nTheirTimestampDiff = 0;
		uint32_t m_nMyTimestampDiff = 0;

		bool m_bWaitWrite, m_bWaitRead, m_bWaitConnect;
		bool m_bEnableFec;
		bool m_bFastAck;
		bool m_bDelayAck;

		std::shared_ptr<CongestionController> m_ptrCongestionController;
		std::shared_ptr<RoundTripMeter> m_ptrRoundTripMeter;
		std::shared_ptr<LostCounter> m_ptrPacketLostCounter;
		std::shared_ptr<UTPClock> m_ptrClocker;


		std::deque<std::shared_ptr<PacketCS>> m_deqNotAckedCmdPacket;//used for sync and close cmd
		std::deque<std::shared_ptr<PacketCS>> m_deqNotAckedDataPacket;


		//std::deque<std::shared_ptr<PacketCS>> m_deqSendTimeOrderedDataPacket;//send order

		std::map<CircleSeq<uint16_t>, std::shared_ptr<PacketCS>> m_mapReceivedPacket;

		std::deque<std::shared_ptr<PacketCS>> m_deqReady4ReadPacket;

		DelaySampleHistroy m_MyDelayHistory;
		DelaySampleHistroy m_RemoteDelayHistory;

	};

}

