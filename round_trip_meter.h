#ifndef __ROUND_TRIP_METER_H__
#define __ROUND_TRIP_METER_H__

#include <cstdint>
#include <math.h>
#include <iostream>
#include <algorithm>

class RoundTripMeter
{
public:
	virtual void OnPacketLost() = 0;
	virtual void OnPacketAcked() = 0;
	virtual void OnPacketAcked(int64_t rtt) = 0;
	virtual int64_t GetTimeoutValue() = 0;
	virtual int64_t GetRTT() = 0;
	virtual void SetBeta(double beta) = 0;
	virtual ~RoundTripMeter() {}
};

class SimpleRoundTripMeter : public RoundTripMeter
{
public:
	const uint32_t MAX_RTT = 8 * 1000 * 1000;
	const uint32_t INIT_RTT = 1 * 1000 * 1000;

	SimpleRoundTripMeter() : m_bFirstTime(true), m_nSRTT(INIT_RTT), m_nRTTVar(0), m_nRTO(INIT_RTT), m_dbBeta(2), m_dbMinBeta(2), m_nContinusTimeoutTimes(0){}
	virtual ~SimpleRoundTripMeter() {}

	virtual void OnPacketLost() 
	{
		
		if (++m_nContinusTimeoutTimes >= 10) {
			m_nContinusTimeoutTimes = 0;
			m_dbBeta *= 2;
			if (m_dbBeta > 1024) {
				m_dbBeta = 1024;
			}
		}
	}

	virtual void OnPacketAcked()
	{
		m_nContinusTimeoutTimes = 0;
		m_dbBeta = m_dbMinBeta;
	}

	virtual void OnPacketAcked(int64_t rtt) 
	{
		if (rtt <= 0) return;

		/*
		m_deqRtt.push_back(rtt);
		if (m_deqRtt.size() > 1000) {
			m_deqRtt.pop_front();
		}
		*/

		m_nContinusTimeoutTimes = 0;
		m_dbBeta = m_dbMinBeta;

		if (m_bFirstTime) {
			m_bFirstTime = false;
			m_nRTTVar = rtt / 2;
			m_nSRTT = rtt;
			m_nRTO = m_nSRTT + 4* m_nRTTVar;
		}
		else {
			m_nRTTVar = 3 * m_nRTTVar / 4 + abs(m_nSRTT - rtt) / 4;
			m_nSRTT = 7 * m_nSRTT / 8 + rtt / 8;
			m_nRTO = m_nSRTT + 4 * m_nRTTVar;
		}

		if (m_nRTO > MAX_RTT) {
			m_nRTO = MAX_RTT;
		}

		
		//std::cout << "raw ttt: "<<rtt<<" smoothed rtt: " << m_nRTO << std::endl;
	}
	virtual int64_t GetTimeoutValue()
	{
		return m_dbBeta * m_nRTO;
	}

	virtual int64_t GetRTT()
	{
		return m_nRTO;
	}

	virtual void SetBeta(double beta)
	{
		m_dbBeta = beta;
		m_dbMinBeta = beta;
	}
private:
	int64_t m_nSRTT;
	int64_t m_nRTTVar;
	int64_t m_nRTO;
	int64_t m_nContinusTimeoutTimes;
	double m_dbBeta;
	double m_dbMinBeta;
	bool m_bFirstTime;

	//std::deque<int64_t> m_deqRtt;//for test
};

#endif