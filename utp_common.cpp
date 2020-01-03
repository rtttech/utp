#include "utp_common.h"

#include <assert.h>
#include <string.h>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <time.h>
#include <random>
#include <iostream>
#include <thread>

namespace rtttech_utp
{

	int GetBitmapBits(CircleSeq<uint16_t> next_expect, CircleSeq<uint16_t> seq_max, int seq_queue_size)
	{
		if (seq_queue_size == 0)
			return 0;

		int bits = uint16_t(seq_max - next_expect);

		return bits;
	}

	int GenerateAckBitfield(CircleSeq<uint16_t> next_expect, const std::vector<CircleSeq<uint16_t>>& seqvec, char* bitbuff, int buffsize)
	{
		memset(bitbuff, 0, buffsize);

		if (seqvec.size() == 0)
			return 0;

		assert(seqvec[0] >= next_expect);

		int pos = 0;
		for (int i = 0; i < seqvec.size(); ++i) {
			pos = uint16_t(seqvec[i] - next_expect -1);
			if (pos / 8 < buffsize)
				BitmapSet(pos, true, bitbuff, buffsize);
			else
				break;
		}

		return (pos + 8) / 8;
	}

	int XorData(const char* data1, int len1, const char* data2, int len2, char* out, int outlen)
	{
		int ret = std::max(len1, len2);

		if (outlen < ret)
			return -1;

		int minlen = std::min(len1, len2);

		for (int i = 0; i < minlen; ++i) {
			out[i] = data1[i] ^ data2[i];
		}

		if (len1 < len2) {
			memcpy(out + minlen, data2 + minlen, ret - minlen);
		}
		else if (len2 < len1) {
			memcpy(out + minlen, data1 + minlen, ret - minlen);
		}
		else {

		}


		return ret;
	}

	void BitmapSet(int pos, bool b, char* buff, int len)
	{
		int nByteIndex = pos / 8;
		int nBitIndex = pos % 8;

		uint8_t ch = '\x01';
		ch <<= nBitIndex;
		if (b) {
			buff[nByteIndex] |= ch;
		}
		else {
			buff[nByteIndex] &= ~ch;
		}
	}

	bool BitmapGet(int pos, const char* buff, int len)
	{
		int nByteIndex = pos / 8;
		int nBitIndex = pos % 8;

		return (buff[nByteIndex] & (static_cast<uint8_t>('\x01') << nBitIndex)) != 0;
	}

	std::string Bitmap01String(const char* buff, int len)
	{
		std::ostringstream oss;

		for (int i = 0; i < len * 8; i++) {
			if (BitmapGet(i, buff, len)) {
				oss << "1";
			}
			else {
				oss << "0";
			}
		}

		std::string ret = oss.str();
		/*if (ret.size() > 0 && ret[0] != '0')
			return ret;*/

		return ret;
	}

	void  AssertFailLog(const char *szExpr, const char *szFile, unsigned int nLine)
	{
		std::cout<<szExpr<<" NOT TRUE!!! File:"<<szFile<<" Line:"<<nLine<<std::endl<<std::flush;
	}

}