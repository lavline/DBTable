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

#include "gen.h"

void gen_trace(std::vector<Packet>& packets, std::vector<int>& check_list, std::vector<Rule>& rules, unsigned int size)
{
    std::random_device seed;
    std::mt19937 rd(seed());
    std::uniform_int_distribution<> dis(0, rules.size() - 1);

    unsigned int protocol[] = { 1,2,3,4,5,6,7,8,17,47,50,51,88,89 };

    unsigned int sip, dip, index;
    unsigned short port;
    unsigned int sip_len, dip_len;
    for (unsigned int i = 0; i < size; i++) {
        Packet p;
        index = dis(rd);
        sip = rules[index].ip.i_32.sip;
        dip = rules[index].ip.i_32.dip;
        sip_len = rules[index].sip_length; dip_len = rules[index].dip_length;
        if (sip_len == 0)sip = rd();
        else if (sip_len < 32) {
            int mbit = 32 - sip_len;
            unsigned int temp = sip >> mbit;
            temp = (temp << mbit) + (rd() % (1 << mbit));
            if (temp >> mbit == sip >> mbit)sip = temp;
            else fprintf(stderr, "Error - gen sip error.\n");
        }
        p.ip.i_32.sip = sip;
        if (dip_len == 0)dip = rd();
        else if (dip_len < 32) {
            int mbit = 32 - dip_len;
            unsigned int temp = dip >> mbit;
            temp = (temp << mbit) + (rd() % (1 << mbit));
            if (temp >> mbit == dip >> mbit)dip = temp;
            else fprintf(stderr, "Error - gen dip error.\n");
        }
        p.ip.i_32.dip = dip;
        for (int i = 0; i < 2; ++i) {
            int Pwidth = rules[index].Port[i][1] - rules[index].Port[i][0];
            if (Pwidth == 0)
                port = rules[index].Port[i][0];
            else {
                port = rd() % Pwidth + rules[index].Port[i][0];
                if (port < rules[index].Port[i][0] || port > rules[index].Port[i][1])
                    fprintf(stderr, "Error - gen sport error.\n");
            }
            p.Port[i] = port;
        }
        if (rules[index].protocol.mask == 0)
            p.protocol = protocol[rd() % (sizeof(protocol) / 4)];
        else
            p.protocol = rules[index].protocol.val;

        check_list.emplace_back(index);
        packets.emplace_back(p);
    }
}

void gen_trace(std::vector<Packet>& packets, std::vector<Rule>& rules, unsigned int size)
{
    std::random_device seed;
    std::mt19937 rd(seed());
    std::uniform_int_distribution<> dis(0, rules.size() - 1);

    unsigned int protocol[] = { 1,2,3,4,5,6,7,8,17,47,50,51,88,89 };

    unsigned int sip, dip, index;
    unsigned short port;
    unsigned int sip_len, dip_len;
    for (unsigned int i = 0; i < size; i++) {
        Packet p;
        index = dis(rd);
        sip = rules[index].ip.i_32.sip;
        dip = rules[index].ip.i_32.dip;
        sip_len = rules[index].sip_length; dip_len = rules[index].dip_length;
        if (sip_len == 0)sip = rd();
        else if (sip_len < 32) {
            int mbit = 32 - sip_len;
            unsigned int temp = sip >> mbit;
            temp = (temp << mbit) + (rd() % (1 << mbit));
            if (temp >> mbit == sip >> mbit)sip = temp;
            else fprintf(stderr, "Error - gen sip error.\n");
        }
        p.ip.i_32.sip = sip;
        if (dip_len == 0)dip = rd();
        else if (dip_len < 32) {
            int mbit = 32 - dip_len;
            unsigned int temp = dip >> mbit;
            temp = (temp << mbit) + (rd() % (1 << mbit));
            if (temp >> mbit == dip >> mbit)dip = temp;
            else fprintf(stderr, "Error - gen dip error.\n");
        }
        p.ip.i_32.dip = dip;
        for (int i = 0; i < 2; ++i) {
            int Pwidth = rules[index].Port[i][1] - rules[index].Port[i][0];
            if (Pwidth == 0)
                port = rules[index].Port[i][0];
            else {
                port = rd() % Pwidth + rules[index].Port[i][0];
                if (port < rules[index].Port[i][0] || port > rules[index].Port[i][1])
                    fprintf(stderr, "Error - gen sport error.\n");
            }
            p.Port[i] = port;
        }
        if (rules[index].protocol.mask == 0)
            p.protocol = protocol[rd() % (sizeof(protocol) / 4)];
        else
            p.protocol = rules[index].protocol.val;
        packets.emplace_back(p);
    }
}

void gen_trace(std::vector<Packet>& packets, std::vector<Rule*>& rules, unsigned int size)
{
    std::random_device seed;
    std::mt19937 rd(seed());
    std::uniform_int_distribution<> dis(0, rules.size() - 1);

    unsigned int protocol[] = { 1,2,3,4,5,6,7,8,17,47,50,51,88,89 };

    unsigned int sip, dip, index;
    unsigned short port;
    unsigned int sip_len, dip_len;
    for (unsigned int i = 0; i < size; i++) {
        Packet p;
        index = dis(rd);
        sip = rules[index]->ip.i_32.sip;
        dip = rules[index]->ip.i_32.dip;
        sip_len = rules[index]->sip_length; dip_len = rules[index]->dip_length;
        if (sip_len == 0)sip = rd();
        else if (sip_len < 32) {
            int mbit = 32 - sip_len;
            unsigned int temp = sip >> mbit;
            temp = (temp << mbit) + (rd() % (1 << mbit));
            if (temp >> mbit == sip >> mbit)sip = temp;
            else fprintf(stderr, "Error - gen sip error.\n");
        }
        p.ip.i_32.sip = sip;
        if (dip_len == 0)dip = rd();
        else if (dip_len < 32) {
            int mbit = 32 - dip_len;
            unsigned int temp = dip >> mbit;
            temp = (temp << mbit) + (rd() % (1 << mbit));
            if (temp >> mbit == dip >> mbit)dip = temp;
            else fprintf(stderr, "Error - gen dip error.\n");
        }
        p.ip.i_32.dip = dip;
        for (int i = 0; i < 2; ++i) {
            int Pwidth = rules[index]->Port[i][1] - rules[index]->Port[i][0];
            if (Pwidth == 0)
                port = rules[index]->Port[i][0];
            else {
                port = rd() % Pwidth + rules[index]->Port[i][0];
                if (port < rules[index]->Port[i][0] || port > rules[index]->Port[i][1])
                    fprintf(stderr, "Error - gen sport error.\n");
            }
            p.Port[i] = port;
        }
        if (rules[index]->protocol.mask == 0)
            p.protocol = protocol[rd() % (sizeof(protocol) / 4)];
        else
            p.protocol = rules[index]->protocol.val;
        packets[i] = p;
    }
}

void gen_trace(Packet& p, unsigned int& check, std::vector<Rule>& rules, unsigned int range)
{
    std::random_device seed;
    std::mt19937 rd(seed());
    std::uniform_int_distribution<> dis(0, range - 1);

    unsigned int protocol[] = { 1,2,3,4,5,6,7,8,17,47,50,51,88,89 };

    unsigned int sip, dip, index;
    unsigned short port;
    unsigned int sip_len, dip_len;

    index = dis(rd);
    sip = rules[index].ip.i_32.sip;
    dip = rules[index].ip.i_32.dip;
    sip_len = rules[index].sip_length; dip_len = rules[index].dip_length;
    if (sip_len == 0)sip = rd();
    else if (sip_len < 32) {
        int mbit = 32 - sip_len;
        unsigned int temp = sip >> mbit;
        temp = (temp << mbit) + (rd() % (1 << mbit));
        if (temp >> mbit == sip >> mbit)sip = temp;
        else fprintf(stderr, "Error - gen sip error.\n");
    }
    p.ip.i_32.sip = sip;
    if (dip_len == 0)dip = rd();
    else if (dip_len < 32) {
        int mbit = 32 - dip_len;
        unsigned int temp = dip >> mbit;
        temp = (temp << mbit) + (rd() % (1 << mbit));
        if (temp >> mbit == dip >> mbit)dip = temp;
        else fprintf(stderr, "Error - gen dip error.\n");
    }
    p.ip.i_32.dip = dip;
    for (int i = 0; i < 2; ++i) {
        int Pwidth = rules[index].Port[i][1] - rules[index].Port[i][0];
        if (Pwidth == 0)
            port = rules[index].Port[i][0];
        else {
            port = rd() % Pwidth + rules[index].Port[i][0];
            if (port < rules[index].Port[i][0] || port > rules[index].Port[i][1])
                fprintf(stderr, "Error - gen sport error.\n");
        }
        p.Port[i] = port;
    }
    if (rules[index].protocol.mask == 0)
        p.protocol = protocol[rd() % (sizeof(protocol) / 4)];
    else
        p.protocol = rules[index].protocol.val;

    check = rules[index].pri;
}
