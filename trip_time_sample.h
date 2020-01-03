#pragma once

#include <stdint.h>
#include <algorithm>
#include <assert.h>

const int DELAY_BASE_SIZE = 2;//last 2 minutes
const int INSTANT_DELAY_SIZE = 4;

inline bool DelayLessThan(uint32_t lhs, uint32_t rhs)
{
	uint32_t mask = 0xFFFFFFFF;
	
	const uint32_t dist_down = (lhs - rhs) & mask;
	const uint32_t dist_up = (rhs - lhs) & mask;

	return dist_up < dist_down;
}

class DelaySampleHistroy {
	
public:
	DelaySampleHistroy()
		:
		m_nLastUpdateBase(0),
		m_nDelayBase(100*1000),
		m_nCurMinuteDelayBase(100*1000)
	{
		
	}

	uint32_t GetBase()
	{
		return m_nDelayBase;
	}


	void AddSample(uint32_t sample, uint64_t nCurTime)
	{
	
		if (m_deqDelayBase.size() == 0) {
			for (size_t i = 0; i < DELAY_BASE_SIZE; i++) {
				// if we don't have a value, set it to the current sample
				m_deqDelayBase.push_back(sample);
			}
			m_nDelayBase = sample;
			m_nCurMinuteDelayBase = sample;
			m_nLastUpdateBase = nCurTime;
		}
		else {
			if (DelayLessThan(sample, m_nCurMinuteDelayBase)) {
				m_nCurMinuteDelayBase = sample;
			}

			if (DelayLessThan(sample, m_nDelayBase)) {
				
				m_nDelayBase = sample;
			}

			const uint32_t delay = sample - m_nDelayBase;
			
			m_deqInstantDelay.push_back(delay);
			if (m_deqInstantDelay.size() > INSTANT_DELAY_SIZE)
				m_deqInstantDelay.pop_front();

			if (nCurTime - m_nLastUpdateBase > 60 * 1000) {
				m_nLastUpdateBase = nCurTime;
				
				m_deqDelayBase.push_back(m_nCurMinuteDelayBase);
				if (m_deqDelayBase.size() > DELAY_BASE_SIZE)
					m_deqDelayBase.pop_front();

				assert(m_deqDelayBase.size() > 0);
				m_nDelayBase = m_deqDelayBase[0];
				for (size_t i = 0; i < m_deqDelayBase.size(); i++) {
					if (DelayLessThan(m_deqDelayBase[i], m_nDelayBase))
						m_nDelayBase = m_deqDelayBase[i];
				}
			}
		}
	}

	uint32_t GetValue()
	{
		uint32_t value = 0xFFFFFFFF;
		for (size_t i = 0; i < m_deqInstantDelay.size(); i++) {
			value = std::min(m_deqInstantDelay[i], value);
		}
		
		return value;
	}


private:
	uint32_t m_nDelayBase;

	uint32_t m_nCurMinuteDelayBase;
	std::deque<uint32_t> m_deqDelayBase;
	uint64_t m_nLastUpdateBase;

	std::deque<uint32_t> m_deqInstantDelay;
};