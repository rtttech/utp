#if !defined(AFX_COMMON_H__FB063327_573C_4D70_A0B4_ECC067B6F4FD__INCLUDED_)
#define AFX_COMMON_H__FB063327_573C_4D70_A0B4_ECC067B6F4FD__INCLUDED_

#include <vector>
#include <stdint.h>
#include <string>
#include <assert.h>
#include <deque>
#include <chrono>

namespace rtttech_utp
{
    inline int64_t GetMicroSecondsSinceEpoch()
    {
        uint64_t us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::
                                                                            now().time_since_epoch()).count();
        return us;
    }
    
	template<class T = uint16_t, class T2 = int16_t>
	class CircleSeq
	{
	public:
		CircleSeq(T seq) : seq_num(seq) {}
		bool operator < (const CircleSeq& r) const { return ((T2)((seq_num)-(r.seq_num)) < 0); }
		bool operator <= (const CircleSeq& r) const { return ((T2)((seq_num)-(r.seq_num)) <= 0); }

		bool operator > (const CircleSeq& r) const { return r < *this; }
		bool operator >= (const CircleSeq& r) const { return r <= *this; }

		bool operator == (const CircleSeq& r) const { return seq_num == r.seq_num; }
		bool operator == (const uint32_t r) const { return seq_num == r; };

		T operator - (const CircleSeq& r) const { return (T)((seq_num)-(r.seq_num)); }
		CircleSeq operator + (const CircleSeq& r) const { return CircleSeq(seq_num + r.seq_num); }

		void operator += (const T r) { seq_num += r; }

		explicit operator T () const { return seq_num; }
	private:
		T seq_num;
	};

	class UTPClock
	{
	public:
		UTPClock() {}
		virtual ~UTPClock() {}

		virtual int64_t GetMicroSecond() const
		{
            return GetMicroSecondsSinceEpoch();
		}
	};

	class LostCounter
	{
	public:
		LostCounter(int duration = 3 * 1000 * 1000, int history = 20)
			: m_nDuration(duration), m_nKeepHistory(history) {}

		void OnPacketAcked(uint64_t tm)
		{
			m_deqLostInfo.push_back(Item(tm, false));
			++m_nTotalPktNum;
			UpdateItem(tm);
		}

		void OnPacketLost(uint64_t tm)
		{
			m_deqLostInfo.push_back(Item(tm, true));
			++m_nLostPktNum;
			++m_nTotalPktNum;
			UpdateItem(tm);
		}

		void UpdateItem(uint64_t tm)
		{
			while (m_deqLostInfo.size() > m_nKeepHistory)
			{
				Item &itm = m_deqLostInfo[0];
				if (tm - m_deqLostInfo[0].time > m_nDuration || tm < m_deqLostInfo[0].time) {

					if (itm.lost) {
						--m_nLostPktNum;
					}
					m_deqLostInfo.pop_front();
					--m_nTotalPktNum;
				}
				else {
					break;
				}
			}
		}

		int GetLostPercent() const
		{
			if (m_nTotalPktNum == 0)
				return 0;
			else
				return 100 * m_nLostPktNum / m_nTotalPktNum;
		}

	private:

		struct Item
		{
			Item(uint64_t tm, bool b) : time(tm), lost(b) {}
			uint64_t time;
			bool lost;
		};

		std::deque<Item> m_deqLostInfo;
		int m_nTotalPktNum = 0;
		int m_nLostPktNum = 0;
		int m_nDuration;
		int m_nKeepHistory;
	};

	void BitmapSet(int pos, bool b, char* buff, int len);
	bool BitmapGet(int pos, const char* buff, int len);
	std::string Bitmap01String(const char* buff, int len);

	int GenerateAckBitfield(CircleSeq<uint16_t> next_expect, const std::vector<CircleSeq<uint16_t>>& seqvec, char* bitbuff, int buffsize);

	int GetBitmapBits(CircleSeq<uint16_t> next_expect, CircleSeq<uint16_t> seq_max, int seq_queue_size);

	int XorData(const char* data1, int len1, const char* data2, int len2, char* out, int outlen);

	std::string GenerateUUID();

	void  AssertFailLog(const char *szExpr, const char *szFile, unsigned int nLine);

#define RTASSERT(expr) if (!(expr)) { AssertFailLog( #expr, __FILE__, __LINE__); assert(expr);}
}

#endif
