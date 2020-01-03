#ifndef __CONGESTION_CONTROL_H__
#define __CONGESTION_CONTROL_H__

#include <cstdint>
#include <iostream>
#include <algorithm>

#include "trip_time_sample.h"
#include "log_helper.h"

const int MAX_WND_SIZE = 16 * 1024 * 1024;

class CongestionController
{
public:
	virtual void OnPacketLost(int64_t time) = 0;
	virtual void OnPacketAcked(int64_t time, int64_t rtt) = 0;
	virtual void OnPacketTripTime(int64_t time, int64_t tt, int64_t rtt, int64_t nOnFlightPacket) = 0;

	virtual uint32_t GetCongestionWnd() = 0;
	virtual ~CongestionController() {}
};

class NullCongestionController : public CongestionController
{
public:
	NullCongestionController(uint32_t nInitWnd) : m_nWnd(nInitWnd) {}
	virtual ~NullCongestionController() {}

	virtual void OnPacketLost(int64_t time) {}
	virtual void OnPacketAcked(int64_t time, int64_t rtt) {}
	virtual void OnPacketTripTime(int64_t time, int64_t tt, int64_t rtt, int64_t nOnFlightPacket) {}
	virtual uint32_t GetCongestionWnd()
	{
		return m_nWnd;
	}
private:
	uint32_t m_nWnd;
};


class LedbatCongestionController : public CongestionController
{
public:
	const uint32_t MAX_CWND_INCREASE_BYTES_PER_RTT = 3000;

	LedbatCongestionController(uint32_t nMTU, uint32_t nInitWnd, uint32_t nTarget = 100*1000/*, std::shared_ptr<spdlog::logger> ptrLogger = nullptr*/)
		: m_nMTU(nMTU), m_nWnd(nInitWnd), m_nControlTarget(nTarget), m_nLastDoLedbat(0)/*, m_ptrLogger(ptrLogger)*/
	{
		
	}
	virtual ~LedbatCongestionController() {}

	virtual void OnPacketLost(int64_t time) 
	{
	
	}
	virtual void OnPacketAcked(int64_t time, int64_t rtt) 
	{
	
	}

	virtual void OnPacketTripTime(int64_t time, int64_t tt, int64_t rtt, int64_t nOnFlightBytes)
	{
		if (tt < 0 || tt > 6 * 1000 * 1000)
			return;

		
		int64_t nOffTarget = m_nControlTarget - tt;
		
		double dbDelayFactor = 1.0*nOffTarget / m_nControlTarget;
		//double dbWindowFactor = 1.0*nOnFlightBytes / m_nWnd;

		double dbWindowFactor = 1.0;

		if (rtt == 0) {
			rtt = 3 * 1000 * 1000;
		}

		int64_t nTimeElapse = rtt;
		if (m_nLastDoLedbat != 0) {
			nTimeElapse = time - m_nLastDoLedbat;
		}

		m_nLastDoLedbat = time;

		double dbScaledGain = MAX_CWND_INCREASE_BYTES_PER_RTT * dbDelayFactor * dbWindowFactor * nTimeElapse / rtt;

		//LOG_DEBUG(m_ptrLogger, "tt:{}, rtt:{}, onflightbytes:{} dbDelayFactor:{}, dbWindowFactor:{}, dbScaledGain:{}, m_nWnd:{}",
		//	tt, rtt, nOnFlightBytes, dbDelayFactor, dbWindowFactor, dbScaledGain, m_nWnd);

		m_nWnd += dbScaledGain;
		

		if (m_nWnd < m_nMTU) {
			m_nWnd = m_nMTU;
		}

		if (m_nWnd > MAX_WND_SIZE) {
			m_nWnd = MAX_WND_SIZE;
		}
	}

	virtual uint32_t GetCongestionWnd()
	{
		return m_nWnd;
	}
private:
	int64_t m_nWnd;
	uint32_t m_nMTU;
	int64_t m_nControlTarget;
	int64_t m_nLastDoLedbat;

	//std::shared_ptr<spdlog::logger> m_ptrLogger;
};


#endif
