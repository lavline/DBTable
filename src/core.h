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


#ifndef __CORE_H_
#define __CORE_H_
#include <iostream>
#include <fstream>
#include <algorithm>
#include <utility>
#include <x86intrin.h>
#include <bitset>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include "util.h"
#include "gen.h"
#include "tss.h"

extern int TOP_K;
extern double END_BOUND;
extern int C_BOUND;
extern int BINTH;

using namespace std;

//extern uint32_t getBit[32];
//extern uint32_t maskBit[33];

class CacuInfo {
public:
	vector<Rule*> rules;
	int threshold;
	int bucket_num;
	int max_bucket_size;
	int target_bucket_num;
	vector<int> fetched_bit_id;

	CacuInfo(vector<Rule*>& _rules, int _threshold);

	MASK simple_extract(int num);
	void CacuIpMask(MASK& mask);
	void fetch_bit_by_ip(int start, int size, BitRank bRank[], vector<CacuRule*>& _rules);
	void partition_by_ip(int bit_id, vector<CacuRule*>& _rules);
	void partition_in_bucket(int start, int size, vector<CacuRule*>& _rules);

	uint16_t CacuPortMask(int type);
	void fetch_bit_by_port(int type, int start, int size, BitRank bRank[], vector<CacuRule*>& _rules);
	void partition_by_port(int type, int bit_id, vector<CacuRule*>& _rules);

	void print_bucket(vector<CacuRule*>& _rules);
};

class DBTable {
public:
	// subsets: [first] pri [second] Subset*
	SubSet subsets;
	vector<Rule*> ruleset;
	int threshold;

	DBTable(vector<Rule>& _rules, int _threshold);
	DBTable(vector<Rule*>& _rules, int _threshold);
	~DBTable();

	void construct();
	void insert_to_ipNode(Rule* _r);
	// void insert_to_tuple();
	void adjust_ipNode(ip_node* _node);
	void adjust_ptuple(prefix_tuple* _tuple);

	uint32_t search(Packet& _p);
	void search_with_log(vector<Packet>& _packets);

	void insert(Rule& _r);
	void remove(Rule& _r);

	void insert_multi_thread(Rule& _r);
	void remove_multi_thread(Rule& _r);

	void print_nodes();
	void mem();
	size_t tuple_mem(Tuple& _tuple);
	size_t ptule_mem(prefix_tuple& _ptuple);
	size_t portNode_mem(port_node* _pnode);
};

#endif // !__CORE_H_
