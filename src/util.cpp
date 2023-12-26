/*
 *	MIT License
 *
 *	Copyright(c) 2022 ShangHai Jiao Tong Univiersity CIT Laboratory.
 *
 *	Permission is hereby granted, free of charge, to any person obtaining a copy
 *	of this softwareand associated documentation files(the "Software"), to deal
 *	in the Software without restriction, including without limitation the rights
 *	to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
 *	copies of the Software, and to permit persons to whom the Software is
 *	furnished to do so, subject to the following conditions :
 *
 *	The above copyright noticeand this permission notice shall be included in all
 *	copies or substantial portions of the Software.
 *
 *	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
 *	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *	SOFTWARE.
 */

#include "util.h"

uint32_t getBit[32] = { 0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x08000000, 0x04000000, 0x02000000, 0x01000000,
						0x00800000, 0x00400000, 0x00200000, 0x00100000, 0x00080000, 0x00040000, 0x00020000, 0x00010000,
						0x00008000, 0x00004000, 0x00002000, 0x00001000, 0x00000800, 0x00000400, 0x00000200, 0x00000100,
						0x00000080, 0x00000040, 0x00000020, 0x00000010, 0x00000008, 0x00000004, 0x00000002, 0x00000001 };


int simple_search(std::vector<Rule>& rules, Packet& _p)
{
	for (auto& _r : rules) {
		MASK _mask = { maskBit[_r.sip_length], maskBit[_r.dip_length] };
		if ((_r.protocol.val & _r.protocol.mask) == (_p.protocol & _r.protocol.mask) &&
			_r.Port[0][0] <= _p.Port[0] && _r.Port[0][1] >= _p.Port[0] &&
			_r.Port[1][0] <= _p.Port[1] && _r.Port[1][1] >= _p.Port[1] &&
			(_r.ip.i_64 & _mask.i_64) == (_p.ip.i_64 & _mask.i_64)) {
			return _r.pri;
		}
	}
	return -1;
}

int check_correct(Rule& a, Packet& b)
{
	if (a.protocol.mask != 0 && (uint32_t)a.protocol.val != b.protocol)return 0;
	int mask = 32 - (uint32_t)a.sip_length;
	if (mask != 32 && (a.ip.i_32.sip >> mask) != (b.ip.i_32.sip >> mask))return 0;
	mask = 32 - (uint32_t)a.dip_length;
	if (mask != 32 && (a.ip.i_32.dip >> mask) != (b.ip.i_32.dip >> mask))return 0;
	if (b.Port[0] < a.Port[0][0] || b.Port[0] > a.Port[0][1] || b.Port[1] < a.Port[1][0] || b.Port[1] > a.Port[1][1])return 0;
	return 1;
}

double get_nano_time(struct timespec* a, struct timespec* b) {
	return (b->tv_sec - a->tv_sec) * 1000000000 + b->tv_nsec - a->tv_nsec;
}
double get_milli_time(struct timespec* a, struct timespec* b) {
	return (b->tv_sec - a->tv_sec) * 1000 + (double)(b->tv_nsec - a->tv_nsec) / 1000000.0;
}

void ana_ruleset(std::vector<Rule>& rules)
{
	int sipBitCount[32][3] = { 0 };
	int dipBitCount[32][3] = { 0 };
	for (auto& _r : rules) {
		for (int i = 0; i < 32; ++i) {
			if (i > _r.sip_length - 1) {
				++sipBitCount[i][2];
			}
			else {
				if (getBit[i] & _r.ip.i_32.sip)++sipBitCount[i][1];
				else ++sipBitCount[i][0];
			}
		}
		for (int i = 0; i < 32; ++i) {
			if (i > _r.dip_length - 1) {
				++dipBitCount[i][2];
			}
			else {
				if (getBit[i] & _r.ip.i_32.dip)++dipBitCount[i][1];
				else ++dipBitCount[i][0];
			}
		}
	}
	double rule_size = rules.size();
	for (int i = 0; i < 3; ++i) {
		for (int j = 0; j < 32; ++j)printf("%f, ", (double)sipBitCount[j][i] / rule_size);
		for (int j = 0; j < 32; ++j)printf("%f, ", (double)dipBitCount[j][i] / rule_size);
		printf("\n");
	}
	for (int j = 0; j < 32; ++j)printf("\'sip%d\', ", j+1);
	for (int j = 0; j < 32; ++j)printf("\'dip%d\', ", j+1);
}


uint32_t hashCode(uint32_t hash1, uint32_t hash2)
{
	hash1 ^= hash1 >> 16;
	hash1 *= 0x85ebca6b;
	hash1 ^= hash1 >> 13;
	hash1 *= 0xc2b2ae35;

	hash2 ^= hash2 >> 16;
	hash2 *= 0x85ebca6b;
	hash2 ^= hash2 >> 13;
	hash2 *= 0xc2b2ae35;

	hash1 ^= hash2;
	hash1 ^= hash1 >> 16;

	return hash1;
}

uint32_t hashCode(uint64_t hash)
{
	uint32_t hash1 = (hash & 0xFFFFFFFF00000000) >> 32;
	uint32_t hash2 = hash & 0x00000000FFFFFFFF;
	
	hash1 ^= hash1 >> 16;
	hash1 *= 0x85ebca6b;
	hash1 ^= hash1 >> 13;
	hash1 *= 0xc2b2ae35;

	hash2 ^= hash2 >> 16;
	hash2 *= 0x85ebca6b;
	hash2 ^= hash2 >> 13;
	hash2 *= 0xc2b2ae35;

	hash1 ^= hash2;
	hash1 ^= hash1 >> 16;

	return hash1;
}
