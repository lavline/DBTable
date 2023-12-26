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

#include "read.h"

int read_rules(const char* file_name, vector<Rule>& list)
{
	FILE* fp = NULL;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "error - can not open rules file\n");
		return 0;
	}
	unsigned int sIp[5];
	unsigned int dIp[5];
	unsigned int sPort[2];
	unsigned int dPort[2];
	unsigned int protocol[2];
	unsigned int i = 0;
	while (fscanf(fp, "@%u.%u.%u.%u/%u\t%u.%u.%u.%u/%u\t%u : %u\t%u : %u\t%x/%x\t%*x/%*x\t\n", &sIp[0], &sIp[1], &sIp[2], &sIp[3], &sIp[4],
		&dIp[0], &dIp[1], &dIp[2], &dIp[3], &dIp[4], &sPort[0], &sPort[1], &dPort[0], &dPort[1], &protocol[1], &protocol[0]) != EOF) {
		//printf("@%u.%u.%u.%u/%u\t%u.%u.%u.%u/%u\t%u : %u\t%u : %u\t0x%02x\n", sIp[0], sIp[1], sIp[2], sIp[3], sIp[4], dIp[0], dIp[1], dIp[2], dIp[3], dIp[4], sPort[0], sPort[1], dPort[0], dPort[1], protocol);
		Rule r;
		r.pri = i;
		r.protocol.mask = protocol[0]; // mask
		r.protocol.val = protocol[1]; // protocol
		r.sip_length = sIp[4];
		r.dip_length = dIp[4];
		int k = 4;
		for (int j = 0; j < 4; j++) {
			r.ip.i_8.sip[j] = (unsigned char)sIp[--k];
			r.ip.i_8.dip[j] = (unsigned char)dIp[k];
		}
		r.mask.i_32.smask = maskBit[r.sip_length]; r.mask.i_32.dmask = maskBit[r.dip_length];
		r.ip.i_64 &= r.mask.i_64;
		r.Port[0][0] = (unsigned short)sPort[0]; r.Port[0][1] = (unsigned short)sPort[1];
		r.Port[1][0] = (unsigned short)dPort[0]; r.Port[1][1] = (unsigned short)dPort[1];
		list.emplace_back(r);
		++i;
	}
	fclose(fp);
	return 1;
}

int read_packets(const char* file_name, vector<Packet>& list, vector<int>& check_list)
{
	FILE* fp = NULL;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "error - can not open trace file\n");
		return 0;
	}
	Packet p = { 0 };
	unsigned int ip_src, ip_des;
	int result;
	while (fscanf(fp, "%u\t%u\t%hu\t%hu\t%u\t%*u\t%d\n", &p.ip.i_32.sip, &p.ip.i_32.dip, &p.Port[0], &p.Port[1], &p.protocol, &result) != EOF) {
		check_list.emplace_back(result);
		list.emplace_back(p);
	}
	fclose(fp);
	return 1;
}

int read_contest_rules(const char* file_name, vector<Rule>& list)
{
	return 0;
}

int read_contest_packets(const char* file_name, vector<Packet>& list, vector<int>& check_list)
{
	return 0;
}
