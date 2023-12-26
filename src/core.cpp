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


#include "core.h"

//uint32_t getBit[32] = { 0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x08000000, 0x04000000, 0x02000000, 0x01000000,
//						0x00800000, 0x00400000, 0x00200000, 0x00100000, 0x00080000, 0x00040000, 0x00020000, 0x00010000,
//						0x00008000, 0x00004000, 0x00002000, 0x00001000, 0x00000800, 0x00000400, 0x00000200, 0x00000100,
//						0x00000080, 0x00000040, 0x00000020, 0x00000010, 0x00000008, 0x00000004, 0x00000002, 0x00000001 };
//uint32_t maskBit[33] = { 0, 0x80000000, 0xC0000000, 0xE0000000, 0xF0000000, 0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000,
//						 0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000, 0xFFF80000, 0xFFFC0000, 0xFFFE0000, 0xFFFF0000,
//						 0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000, 0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
//						 0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF };
int TOP_K = 4;
double END_BOUND = 0.8;
int C_BOUND = 32;
int BINTH = 4;

CacuInfo::CacuInfo(vector<Rule*>& _rules, int _threshold) : rules(_rules), threshold(_threshold), bucket_num(0), max_bucket_size(0), target_bucket_num(0){}

MASK CacuInfo::simple_extract(int num)
{
	MASK mask = { 0 };
	vector<int> bit_id;
	int sipBitCount[32][3] = { 0 };
	int dipBitCount[32][3] = { 0 };
	for (auto& _r : rules) {
		for (int i = 0; i < 32; ++i) {
			if (i > _r->sip_length - 1) {
				++sipBitCount[i][2];
			}
			else {
				if (getBit[i] & _r->ip.i_32.sip)++sipBitCount[i][1];
				else ++sipBitCount[i][0];
			}
		}
		for (int i = 0; i < 32; ++i) {
			if (i > _r->dip_length - 1) {
				++dipBitCount[i][2];
			}
			else {
				if (getBit[i] & _r->ip.i_32.dip)++dipBitCount[i][1];
				else ++dipBitCount[i][0];
			}
		}
	}
	BitRank tmpRank[64] = { 0 };
	for (int i = 0; i < 32; ++i) {
		tmpRank[i].id = i;
		tmpRank[i].rank = (double)(abs(sipBitCount[i][0] - sipBitCount[i][1]) + sipBitCount[i][2]) / rules.size();
	}
	for (int i = 0; i < 32; ++i) {
		tmpRank[i + 32].id = i + 32;
		tmpRank[i + 32].rank = (double)(abs(dipBitCount[i][0] - dipBitCount[i][1]) + dipBitCount[i][2]) / rules.size();
	}

	sort(tmpRank, tmpRank + 64, [](BitRank a, BitRank b)-> bool {return a.rank < b.rank; });

	for (int i = 0; i < num; ++i) {
		if (tmpRank[i].id < 32)mask.i_32.smask |= getBit[tmpRank[i].id];
		else mask.i_32.dmask |= getBit[tmpRank[i].id - 32];
		bit_id.emplace_back(tmpRank[i].id);
	}
	sort(bit_id.begin(), bit_id.end());
	cout << "\nsimple extract bits:\n";
	for (auto x : bit_id)cout << x << " ";
	cout << endl << endl;
	return mask;
}

void CacuInfo::CacuIpMask(MASK& mask)
{
	mask.i_64 = 0;
	vector<CacuRule*> _rules;
	for (auto& _r : rules) {
		//CacuRule* rule = (CacuRule*)malloc(sizeof(CacuRule));
		CacuRule* rule = new CacuRule;
		memcpy(rule, _r, sizeof(Rule));
		_rules.emplace_back(rule);
	}
	_rules[0]->is_first = true;
	_rules[0]->size = _rules.size();

	int dbs_size = 0;

	while (true) {
		BitRank bRank[64] = { 0 };
		for (int i = 0; i < 64; ++i)bRank[i].id = i;
		for (int i = 0; i < _rules.size();) {
			//if (_rules[i]->is_first) {
				fetch_bit_by_ip(i, _rules[i]->size, bRank, _rules);
				i += _rules[i]->size;
			//}
		}
		sort(bRank, bRank + 64, [](BitRank a, BitRank b)-> bool {if (a.count != b.count)return a.count > b.count; else return a.rank < b.rank; });
		//cout << bRank[0].id << endl;
		int old_target_bucket_num = target_bucket_num;
		int old_max_bucket_size = max_bucket_size;
		int old_bucket_num = bucket_num;
		partition_by_ip(bRank[0].id, _rules);
		if (target_bucket_num == old_target_bucket_num && old_max_bucket_size == max_bucket_size && old_bucket_num == bucket_num)break;
		if (bRank[0].id < 32)mask.i_32.smask |= getBit[bRank[0].id];
		else mask.i_32.dmask |= getBit[bRank[0].id - 32];
		//fetched_bit_id.emplace_back(bRank[0].id);
		++dbs_size;
		if (((double)target_bucket_num / (double)bucket_num) > END_BOUND)break;
	}

	print_bucket(_rules);
	printf("\nDBS size: %d\n\n", dbs_size);
	//sort(fetched_bit_id.begin(), fetched_bit_id.end());
	//for (auto x : fetched_bit_id)cout << x << " ";

	// compare with simple extract
	//mask = simple_extract(fetched_bit_id.size());

	//cout << endl << endl;

	//for (auto& _r : _rules)free(_r);
	for (auto _r : _rules)delete _r;
}

void CacuInfo::fetch_bit_by_ip(int start, int size, BitRank bRank[], vector<CacuRule*>& _rules)
{
	int sipBitCount[32][3] = { 0 };
	int dipBitCount[32][3] = { 0 };
	for (int j = start; j < start + size; ++j) {
		for (int i = 0; i < 32; ++i) {
			if (i > _rules[j]->sip_length - 1) {
				++sipBitCount[i][2];
			}
			else {
				if (getBit[i] & _rules[j]->ip.i_32.sip)++sipBitCount[i][1];
				else ++sipBitCount[i][0];
			}
		}
		for (int i = 0; i < 32; ++i) {
			if (i > _rules[j]->dip_length - 1) {
				++dipBitCount[i][2];
			}
			else {
				if (getBit[i] & _rules[j]->ip.i_32.dip)++dipBitCount[i][1];
				else ++dipBitCount[i][0];
			}
		}
	}
	BitRank tmpRank[64] = { 0 };
	for (int i = 0; i < 32; ++i) {
		tmpRank[i].id = i;
		tmpRank[i].rank = (double)(abs(sipBitCount[i][0] - sipBitCount[i][1]) + sipBitCount[i][2]) / size;
	}
	for (int i = 0; i < 32; ++i) {
		tmpRank[i + 32].id = i + 32;
		tmpRank[i + 32].rank = (double)(abs(dipBitCount[i][0] - dipBitCount[i][1]) + dipBitCount[i][2]) / size;
	}

	sort(tmpRank, tmpRank + 64, [](BitRank a, BitRank b)-> bool {return a.rank < b.rank; });

	for (int i = 0; i < TOP_K; ++i) {
		bRank[tmpRank[i].id].count += size;
		bRank[tmpRank[i].id].rank += tmpRank[i].rank;
	}
}

void CacuInfo::partition_by_ip(int bit_id, vector<CacuRule*>& _rules)
{
	MASK _mask = { 0 };
	if (bit_id < 32)_mask.i_32.smask = getBit[bit_id];
	else _mask.i_32.dmask = getBit[bit_id - 32];

	for (auto& _r : _rules) {
		if ((bit_id < 32 && _r->sip_length - 1 < bit_id) || (bit_id >= 32 && _r->dip_length - 1 < (bit_id - 32))) {
			_r->fetch_bit = 2;
		}
		else if (_r->ip.i_64 & _mask.i_64) {
			_r->fetch_bit = 1;
		}
		else {
			_r->fetch_bit = 0;
		}
	}


	for (int i = 0; i < _rules.size();) {
		int _step = _rules[i]->size;
		partition_in_bucket(i, _step, _rules);
		i += _step;
	}

	//print_bucket(_rules);

	int target_num = 0;
	int max_size = 0;
	int total_num = 0;
	for (auto _r : _rules) {
		if (_r->is_first) {
			++total_num;
			if (_r->size < threshold)++target_num;
			if (max_size < _r->size)max_size = _r->size;
		}
	}
	if (target_num != target_bucket_num || max_size != max_bucket_size || total_num != bucket_num) {
		target_bucket_num = target_num;
		bucket_num = total_num;
		max_bucket_size = max_size;
	}
}

void CacuInfo::partition_in_bucket(int start, int size, vector<CacuRule*>& _rules)
{
	sort(_rules.begin() + start, _rules.begin() + start + size,
		[](CacuRule* a, CacuRule* b) -> bool {
			if (a->fetch_bit == b->fetch_bit)return a->pri < b->pri;
			else return a->fetch_bit < b->fetch_bit; });

	_rules[start + size - 1]->size = 1;
	for (int i = start + size - 2; i >= start; --i) {
		if (_rules[i]->fetch_bit == _rules[i + 1]->fetch_bit) {
			_rules[i + 1]->is_first = false;
			_rules[i]->size = _rules[i + 1]->size + 1;
		}
		else {
			_rules[i + 1]->is_first = true;
			_rules[i]->size = 1;
		}
	}
	_rules[start]->is_first = true;
}

uint16_t CacuInfo::CacuPortMask(int type)
{
	uint16_t mask = 0;
	vector<CacuRule*> _rules;
	for (auto& _r : rules) {
		CacuRule* rule = new CacuRule;
		memcpy(rule, _r, sizeof(Rule));
		_rules.emplace_back(rule);
	}
	_rules[0]->is_first = true;
	_rules[0]->size = _rules.size();

	while (true) {
		BitRank bRank[16] = { 0 };
		for (int i = 0; i < 16; ++i)bRank[i].id = i;
		for (int i = 0; i < _rules.size();) {
			fetch_bit_by_port(type, i, _rules[i]->size, bRank, _rules);
			i += _rules[i]->size;
		}
		sort(bRank, bRank + 16, [](BitRank a, BitRank b)-> bool {if (a.count != b.count)return a.count > b.count; else return a.rank < b.rank; });
		int old_target_bucket_num = target_bucket_num;
		int old_max_bucket_size = max_bucket_size;
		int old_bucket_num = bucket_num;
		partition_by_port(type, bRank[0].id, _rules);
		if (target_bucket_num == old_target_bucket_num && old_max_bucket_size == max_bucket_size && old_bucket_num == bucket_num)break;
		mask |= (uint16_t)getBit[bRank[0].id + 16];
		//fetched_bit_id.emplace_back(bRank[0].id);
		if (((double)target_bucket_num / (double)bucket_num) > END_BOUND)break;
	}

	//print_bucket(_rules);
	//sort(fetched_bit_id.begin(), fetched_bit_id.end());
	/*for (auto x : fetched_bit_id)cout << x << " ";
	cout << endl << endl;*/

	for (auto& _r : _rules)delete _r;

	return mask;
}

void CacuInfo::fetch_bit_by_port(int type, int start, int size, BitRank bRank[], vector<CacuRule*>& _rules)
{
	int portBitCount[16][2] = { 0 };
	for (int j = start; j < start + size; ++j) {
		for (int i = 0; i < 16; ++i) {
			if (_rules[j]->Port[type][0] & getBit[i + 16])++portBitCount[i][1];
			else ++portBitCount[i][0];
		}
	}
	BitRank tmpRank[16] = { 0 };
	for (int i = 0; i < 16; ++i) {
		tmpRank[i].id = i;
		tmpRank[i].rank = (double)(abs(portBitCount[i][0] - portBitCount[i][1])) / size;
	}

	sort(tmpRank, tmpRank + 16, [](BitRank a, BitRank b)-> bool {return a.rank < b.rank; });

	for (int i = 0; i < TOP_K; ++i) {
		bRank[tmpRank[i].id].count += size;
		bRank[tmpRank[i].id].rank += tmpRank[i].rank;
	}
}

void CacuInfo::partition_by_port(int type, int bit_id, vector<CacuRule*>& _rules)
{
	uint16_t _mask = getBit[bit_id + 16];

	for (auto& _r : _rules) {
		if (_r->Port[type][0] & _mask)_r->fetch_bit = 1;
		else _r->fetch_bit = 0;
	}


	for (int i = 0; i < _rules.size();) {
		int _step = _rules[i]->size;
		partition_in_bucket(i, _step, _rules);
		i += _step;
	}

	//print_bucket(_rules);

	int target_num = 0;
	int max_size = 0;
	int total_num = 0;
	for (auto _r : _rules) {
		if (_r->is_first) {
			++total_num;
			if (_r->size < threshold)++target_num;
			if (max_size < _r->size)max_size = _r->size;
		}
	}
	if (target_num != target_bucket_num || max_size != max_bucket_size || total_num != bucket_num) {
		target_bucket_num = target_num;
		bucket_num = total_num;
		max_bucket_size = max_size;
	}
}

void CacuInfo::print_bucket(vector<CacuRule*>& _rules)
{
	FILE* fp = NULL;
	fp = fopen("buckets.txt", "a");
	if (fp == NULL) {
		fprintf(stderr, "error - can not creat buckets.txt\n");
		return;
	}
	fprintf(fp, "Buckets Information [SIZE SIG]  (SIG={[0, 0], (0, 10], (10, 50], (50, 100], (100, +)})\n");
	fprintf(fp, "                  |- RULE\n");
	fprintf(fp, "                  |- ...\n");
	
	int bound_1 = 11;
	int bound_2 = 51;
	int bound_3 = 101;
	int small_bucket = 0;
	int mid_bucket = 0;
	int big_bucket = 0;

	for (size_t i = 0; i < _rules.size(); ++i) {
		if (_rules[i]->is_first) {
			int _bucket_size = _rules[i]->size;
			fprintf(fp, "\nSIZE= %d ", _bucket_size);
			if (_bucket_size < bound_1) {
				fprintf(fp, "(0, 10]\n");
			}
			else if (_bucket_size < bound_2) {
				fprintf(fp, "(10, 50]\n");
				++small_bucket;
			}
			else if (_bucket_size < bound_3) {
				fprintf(fp, "(50, 100]\n");
				++mid_bucket;
			}
			else {
				fprintf(fp, "(100, +)\n");
				++big_bucket;
			}
			for (int j = 0; j < _bucket_size; ++j) {
				fprintf(fp, "|- %u\t%u.%u.%u.%u/%u\t%u.%u.%u.%u/%u\t%u:%u\t%u:%u\t%d\n",
					_rules[i+j]->pri, _rules[i+j]->ip.i_8.sip[3], _rules[i+j]->ip.i_8.sip[2],
					_rules[i+j]->ip.i_8.sip[1], _rules[i+j]->ip.i_8.sip[0], _rules[i+j]->sip_length,
					_rules[i+j]->ip.i_8.dip[3], _rules[i+j]->ip.i_8.dip[2], _rules[i+j]->ip.i_8.dip[1],
					_rules[i+j]->ip.i_8.dip[0], _rules[i+j]->dip_length, _rules[i+j]->Port[0][0], _rules[i + j]->Port[0][1],
					_rules[i+j]->Port[1][0], _rules[i+j]->Port[1][1], _rules[i + j]->fetch_bit);
			}
		}
	}
	fclose(fp);

	
	printf("buckets        : %d\n", bucket_num);
	printf("max bucket size: %d\n", max_bucket_size);
	printf("target buckets : %d %f\%\n", target_bucket_num, (double)target_bucket_num / (double)bucket_num * 100);
	printf("(10,50]        : %d %f\%\n", small_bucket, (double)small_bucket / (double)bucket_num * 100);
	printf("(50,100]       : %d %f\%\n", mid_bucket, (double)mid_bucket / (double)bucket_num * 100);
	printf("big cell       : %d %f\%\n", big_bucket, (double)big_bucket / (double)bucket_num * 100);
}

DBTable::DBTable(vector<Rule>& _rules, int _threshold) : threshold(_threshold)
{
	for (auto& _r : _rules) {
		ruleset.emplace_back(&_r);
	}
}

DBTable::DBTable(vector<Rule*>& _rules, int _threshold) : ruleset(_rules), threshold(_threshold){}

DBTable::~DBTable()
{
	for (int i = 0; i < subsets.size; ++i) {
		for (auto& _tuple : subsets.ipNodes[i].tuples) {
			for (int j = 0; j < _tuple.mask + 1; ++j) {
				// delete ptuple
				if (_tuple.ptuples[j].next != NULL) {
					prefix_tuple* _ptuple = _tuple.ptuples[j].next;
					while (_ptuple != NULL) {
						// delete port node
						for (int k = 0; k < 2; ++k) {
							if (_ptuple->pNodes[k] != NULL) {
								bitset<16> bits = _ptuple->pNodes[k]->mask;
								delete[] _ptuple->pNodes[k]->buckets;
							}
						}
						prefix_tuple* del_ptuple = _ptuple;
						_ptuple = _ptuple->next;
						delete del_ptuple;
					}
				}
			}
			delete[] _tuple.ptuples;
		}
		if (subsets.ipNodes[i].prefix_down != NULL) {
			for (int j = 0; j < 33; ++j) {
				for (int k = 0; k < 33; ++k) {
					delete[] subsets.ipNodes[i].prefix_down[j][k];
				}
				delete[] subsets.ipNodes[i].prefix_down[j];
			}
			delete[] subsets.ipNodes[i].prefix_down;
		}
	}
	delete[] subsets.ipNodes;
}

void DBTable::construct()
{
	CacuInfo cacu(ruleset, threshold);
	cacu.CacuIpMask(subsets.mask);
	uint32_t bucket_num = 0;
	bitset<64> bits;
	bits = subsets.mask.i_64;
	bucket_num = (1 << bits.count()) + 1;
	subsets.size = bucket_num;
	subsets.ipNodes = new ip_node [bucket_num]();
	subsets.nodes_num = bucket_num;

	for (auto _r : ruleset) insert_to_ipNode(_r);
	for (int j = 0; j < bucket_num; ++j) {
		if (subsets.ipNodes[j].pri != 0xFFFFFFFF && subsets.ipNodes[j].rules.size() > C_BOUND)
			adjust_ipNode(&subsets.ipNodes[j]);
	}
	print_nodes();
}

void DBTable::insert_to_ipNode(Rule* _r)
{
	MASK _mask = { maskBit[_r->sip_length], maskBit[_r->dip_length] };
	uint32_t idx = (_mask.i_64 & subsets.mask.i_64) == subsets.mask.i_64 ? _pext_u64(_r->ip.i_64 & _mask.i_64, subsets.mask.i_64) : (subsets.size - 1);
	if (subsets.ipNodes[idx].pri > _r->pri)subsets.ipNodes[idx].pri = _r->pri;
	subsets.ipNodes[idx].rules.emplace_back(*_r);
	//printf("%u\n", subsets.ipNodes[idx].rules[0].protocol);
}

void DBTable::adjust_ipNode(ip_node* _node)
{
	vector<Rule*> _rules;
	vector<TupleRange> tuple_ranges;
	//char prefix_down[33][33][2];
	double dt_time = 0;
	//for (auto& _r : _node->rules)_rules.emplace_back(&_r);
	for (int i = 0; i < _node->rules.size(); ++i)_rules.emplace_back(&_node->rules[i]);
	tuple_ranges = DynamicTupleRanges(_rules, dt_time, tuple_ranges);
	int tuple_ranges_num = tuple_ranges.size();

	_node->prefix_down = new char** [33]();
	for (int i = 0; i < 33; ++i) {
		_node->prefix_down[i] = new char* [33]();
		for (int j = 0; j < 33; ++j)_node->prefix_down[i][j] = new char[2]();
	}

	for (int i = 0; i < tuple_ranges_num; ++i)
		for (int x = tuple_ranges[i].x1; x <= tuple_ranges[i].x2; ++x)
			for (int y = tuple_ranges[i].y1; y <= tuple_ranges[i].y2; ++y) {
				_node->prefix_down[x][y][0] = tuple_ranges[i].x1;
				_node->prefix_down[x][y][1] = tuple_ranges[i].y1;
			}


	vector<MASK> p_length;

	// adjust rules
	//for (auto& _r : _node->rules) {
	for (int rid = 0; rid < _node->rules.size(); ++rid) {
		auto& _r = _node->rules[rid];
		if (_r.pri == 79960) {
			printf("\n");
		}
		MASK key = { maskBit[_node->prefix_down[_r.sip_length][_r.dip_length][0]], maskBit[_node->prefix_down[_r.sip_length][_r.dip_length][1]] };
		int i = 0;
		// find tuple
		for (; i < p_length.size(); ++i)if (key.i_64 == p_length[i].i_64)break;
		// creat tuple
		if (i == p_length.size()) {
			p_length.emplace_back(key);
			_node->tuples.emplace_back(Tuple(key));
			_node->tuples[i].pri = _r.pri;
			_node->tuples[i].ptuples = new prefix_tuple[8]();
		}
		Tuple* _tuple = &_node->tuples[i];
		// expansion hashtable
		if (_tuple->ptuple_num >= 0.75 * (_tuple->mask + 1)) {
			uint32_t new_mask = (_tuple->mask + 1) << 1;
			prefix_tuple* new_pTuples = new prefix_tuple[new_mask]();
			--new_mask;
			for (int j = 0; j < _tuple->mask + 1; ++j) {
				prefix_tuple* _tmp = &_tuple->ptuples[j];
				if (_tmp->pri != 0xFFFFFFFF) {
					uint32_t new_hash_id = hashCode(_tmp->prefix.i_32.sip, _tmp->prefix.i_32.dip) & new_mask;
					if (new_pTuples[new_hash_id].pri == 0xFFFFFFFF) {
						new_pTuples[new_hash_id] = *_tmp;
						//_tmp = _tmp->next;
						new_pTuples[new_hash_id].next = NULL;
					}
					else {
						prefix_tuple* iter1 = &new_pTuples[new_hash_id];
						prefix_tuple* iter2 = &new_pTuples[new_hash_id];
						while (iter2 != NULL) {
							if (_tmp->pri < iter2->pri)break;
							iter1 = iter2;
							iter2 = iter2->next;
						}
						prefix_tuple* _tmp1 = _tmp;
						//_tmp = _tmp->next;
						if (iter1 == iter2) {
							prefix_tuple* _tcopy = new prefix_tuple();
							*_tcopy = new_pTuples[new_hash_id];
							new_pTuples[new_hash_id] = *_tmp1;
							new_pTuples[new_hash_id].next = _tcopy;
						}
						else {
							prefix_tuple* _tcopy = new prefix_tuple();
							*_tcopy = *_tmp1;
							iter1->next = _tcopy;
							_tcopy->next = iter2;
						}
					}
				}
				_tmp = _tmp->next;
				while (_tmp != NULL) {
					uint32_t new_hash_id = hashCode(_tmp->prefix.i_32.sip, _tmp->prefix.i_32.dip) & new_mask;
					if (new_pTuples[new_hash_id].pri == 0xFFFFFFFF) {
						new_pTuples[new_hash_id] = *_tmp;
						new_pTuples[new_hash_id].next = NULL;
						prefix_tuple* del_pt = _tmp;
						_tmp = _tmp->next;
						delete del_pt;
					}
					else {
						prefix_tuple* iter1 = &new_pTuples[new_hash_id];
						prefix_tuple* iter2 = &new_pTuples[new_hash_id];
						while (iter2 != NULL) {
							if (_tmp->pri < iter2->pri)break;
							iter1 = iter2;
							iter2 = iter2->next;
						}
						prefix_tuple* _tmp1 = _tmp;
						_tmp = _tmp->next;
						if (iter1 == iter2) {
							prefix_tuple _tcopy = *_tmp1;
							*_tmp1 = new_pTuples[new_hash_id];
							new_pTuples[new_hash_id] = _tcopy;
							new_pTuples[new_hash_id].next = _tmp1;
						}
						else {
							iter1->next = _tmp1;
							_tmp1->next = iter2;
						}
					}
				}
			}
			delete[] _tuple->ptuples;
			_tuple->ptuples = new_pTuples;
			_tuple->mask = new_mask;
		}
		// insert
		IP p_key = { _r.ip.i_64 & key.i_64 };
		uint32_t idx = hashCode(p_key.i_32.sip, p_key.i_32.dip) & _tuple->mask;
		if (_tuple->ptuples[idx].pri == 0xFFFFFFFF) {
			_tuple->ptuples[idx].pri = _r.pri;
			_tuple->ptuples[idx].prefix = p_key;
			_tuple->ptuples[idx].rules.emplace_back(_r);
			++_tuple->ptuple_num;
		}
		else {
			prefix_tuple* _pTuple = &_tuple->ptuples[idx];
			prefix_tuple* prior;
			while (_pTuple != NULL)
			{
				if (_pTuple->prefix.i_64 == p_key.i_64) {
					_pTuple->rules.emplace_back(_r);
					break;
				}
				prior = _pTuple;
				_pTuple = _pTuple->next;
			}
			if (_pTuple == NULL) {
				prefix_tuple* new_ptuple = new prefix_tuple();
				new_ptuple->pri = _r.pri;
				new_ptuple->prefix = p_key;
				new_ptuple->rules.emplace_back(_r);
				prior->next = new_ptuple;
				++_tuple->ptuple_num;
			}
		}
	}
	// free node->rules
	//vector<Rule>().swap(_node->rules);
	_node->rules.free();

	// adjust ptuple
	for (auto& _tuple : _node->tuples) {
		for (int i = 0; i < _tuple.mask + 1; ++i) {
			prefix_tuple* _ptuple = &_tuple.ptuples[i];
			while (_ptuple != NULL && _ptuple->pri != 0xFFFFFFFF) {
				if (_ptuple->rules.size() > 8)adjust_ptuple(_ptuple);
				_ptuple = _ptuple->next;
			}
			
		}
	}
}

void DBTable::adjust_ptuple(prefix_tuple* _ptuple)
{
	vector<Rule*> _ruleset[2];
	myVector<Rule> _rules;
	//for (auto& _r : _ptuple->rules)
	for (int i = 0; i < _ptuple->rules.size(); ++i) {
		auto& _r = _ptuple->rules[i];
		if (_r.Port[1][0] == _r.Port[1][1])_ruleset[1].emplace_back(&_r);
		else if (_r.Port[0][0] == _r.Port[0][1])_ruleset[0].emplace_back(&_r);
		else _rules.emplace_back(_r);
	}

	for (int i = 0; i < 2; ++i) {
		if (_ruleset[i].size() != 0) {
			_ptuple->pNodes[i] = new port_node();
			_ptuple->pNodes[i]->pri = _ruleset[i][0]->pri;
			_ptuple->pNodes[i]->type = i;
			CacuInfo cacu(_ruleset[i], 4);
			_ptuple->pNodes[i]->mask = cacu.CacuPortMask(i);
			bitset<16> bits = _ptuple->pNodes[i]->mask;
			_ptuple->pNodes[i]->buckets = new Bucket [(1 << bits.count())]();
			for (auto _r : _ruleset[i]) {
				int idx = _pext_u32(_r->Port[i][0], _ptuple->pNodes[i]->mask);
				if (_ptuple->pNodes[i]->buckets[idx].pri > _r->pri) {
					_ptuple->pNodes[i]->buckets[idx].pri = _r->pri;
				}
				_ptuple->pNodes[i]->buckets[idx].rules.emplace_back(*_r);
			}
		}
	}

	_ptuple->rules.swap(_rules);
}

uint32_t DBTable::search(Packet& _p)
{
	uint32_t res = 0xFFFFFFFF;
	uint32_t bucket_id[2] = { _pext_u64(_p.ip.i_64, subsets.mask.i_64), subsets.nodes_num - 1 };
	// search in subset
	for (int j = 0; j < 2; ++j) {
		if (res > subsets.ipNodes[bucket_id[j]].pri) {
			// search in first layer
			if (!subsets.ipNodes[bucket_id[j]].rules.empty()) {
				//for (auto& _r : subsets.ipNodes[bucket_id[j]].rules) {
				for (int rid = 0; rid < subsets.ipNodes[bucket_id[j]].rules.size(); ++rid) {
					auto& _r = subsets.ipNodes[bucket_id[j]].rules[rid];
					if (res < _r.pri)break;
					MASK _mask = { maskBit[_r.sip_length], maskBit[_r.dip_length] };
					if ((_r.ip.i_64 ^ _p.ip.i_64 & _r.mask.i_64) == 0 && (_r.protocol.val & _r.protocol.mask) == (_p.protocol & _r.protocol.mask) &&
						_r.Port[0][0] <= _p.Port[0] && _r.Port[0][1] >= _p.Port[0] &&
						_r.Port[1][0] <= _p.Port[1] && _r.Port[1][1] >= _p.Port[1]) {
						res = _r.pri;
						break;
					}
				}
			}
			//else {
				// search in tuple
				for (auto& _tuple : subsets.ipNodes[bucket_id[j]].tuples) {
					if (_tuple.pri > res)break;
					IP _prefix = { _p.ip.i_64 & _tuple.key.i_64 };
					uint32_t hash1 = _prefix.i_32.sip;
					uint32_t hash2 = _prefix.i_32.dip;
					hash1 ^= hash1 >> 16; hash1 *= 0x85ebca6b; hash1 ^= hash1 >> 13; hash1 *= 0xc2b2ae35;
					hash2 ^= hash2 >> 16; hash2 *= 0x85ebca6b; hash2 ^= hash2 >> 13; hash2 *= 0xc2b2ae35;
					hash1 ^= hash2; hash1 ^= hash1 >> 16;
					prefix_tuple* _ptuple = &_tuple.ptuples[hash1 & _tuple.mask];
					while (_ptuple != NULL) {
						if (_ptuple->pri > res)break;
						// search in ptuple
						if (_prefix.i_64 == _ptuple->prefix.i_64) {
							// search in second layer
							if (!_ptuple->rules.empty()) {
								//for (auto& _r : _ptuple->rules) {
								for (int rid = 0; rid < _ptuple->rules.size(); ++rid) {
									auto& _r = _ptuple->rules[rid];
									if (res < _r.pri)break;
									if ((_r.ip.i_64 ^ _p.ip.i_64 & _r.mask.i_64) == 0 && (_r.protocol.val & _r.protocol.mask) == (_p.protocol & _r.protocol.mask) &&
										_r.Port[0][0] <= _p.Port[0] && _r.Port[0][1] >= _p.Port[0] &&
										_r.Port[1][0] <= _p.Port[1] && _r.Port[1][1] >= _p.Port[1]) {
										res = _r.pri;
										break;
									}
								}
							}
							// search in port_node
							for (int k = 0; k < 2; ++k) {
								if (_ptuple->pNodes[k] == NULL || _ptuple->pNodes[k]->pri > res)continue;
								uint32_t pn_id = _pext_u32(_p.Port[_ptuple->pNodes[k]->type], _ptuple->pNodes[k]->mask);
								if (res > _ptuple->pNodes[k]->buckets[pn_id].pri) {
									//for (auto& _r : _ptuple->pNodes[k]->buckets[pn_id].rules) {
									for (int rid = 0; rid < _ptuple->pNodes[k]->buckets[pn_id].rules.size(); ++rid) {
										auto& _r = _ptuple->pNodes[k]->buckets[pn_id].rules[rid];
										if (res < _r.pri)break;
										if ((_r.ip.i_64 ^ _p.ip.i_64 & _r.mask.i_64) == 0 && (_r.protocol.val & _r.protocol.mask) == (_p.protocol & _r.protocol.mask) &&
											_r.Port[0][0] <= _p.Port[0] && _r.Port[0][1] >= _p.Port[0] &&
											_r.Port[1][0] <= _p.Port[1] && _r.Port[1][1] >= _p.Port[1]) {
											res = _r.pri;
											break;
										}
									}
								}
							}
							break;
						}
						_ptuple = _ptuple->next;
					}
				}
			//}
		}
	}
	return res;
}

void DBTable::search_with_log(vector<Packet>& _packet)
{
	uint64_t acc_bucket = 0;
	uint64_t acc_tuple = 0;
	uint64_t acc_rule = 0;
	int max_bucket = 0;
	int max_tuple = 0;
	int max_rule = 0;
	for (auto& _p : _packet) {
		int acc_b, acc_t, acc_r;
		acc_b = acc_t = acc_r = 0;
		uint32_t res = 0xFFFFFFFF;
		uint32_t bucket_id[2] = { _pext_u64(_p.ip.i_64, subsets.mask.i_64), subsets.nodes_num - 1 };
		// search in subset
		for (int j = 0; j < 2; ++j) {
			if (res > subsets.ipNodes[bucket_id[j]].pri) {
				++acc_b;
				// search in first layer
				if (!subsets.ipNodes[bucket_id[j]].rules.empty()) {
					//for (auto& _r : subsets.ipNodes[bucket_id[j]].rules) {
					for (int rid = 0; rid < subsets.ipNodes[bucket_id[j]].rules.size(); ++rid) {
						++acc_r;
						auto& _r = subsets.ipNodes[bucket_id[j]].rules[rid];
						if (res < _r.pri)break;
						MASK _mask = { maskBit[_r.sip_length], maskBit[_r.dip_length] };
						if ((_r.ip.i_64 ^ _p.ip.i_64 & _r.mask.i_64) == 0 && (_r.protocol.val & _r.protocol.mask) == (_p.protocol & _r.protocol.mask) &&
							_r.Port[0][0] <= _p.Port[0] && _r.Port[0][1] >= _p.Port[0] &&
							_r.Port[1][0] <= _p.Port[1] && _r.Port[1][1] >= _p.Port[1]) {
							res = _r.pri;
							break;
						}
					}
				}
				else {
					// search in tuple
					for (auto& _tuple : subsets.ipNodes[bucket_id[j]].tuples) {
						if (_tuple.pri > res)break;
						++acc_t;
						IP _prefix = { _p.ip.i_64 & _tuple.key.i_64 };
						uint32_t hash1 = _prefix.i_32.sip;
						uint32_t hash2 = _prefix.i_32.dip;
						hash1 ^= hash1 >> 16; hash1 *= 0x85ebca6b; hash1 ^= hash1 >> 13; hash1 *= 0xc2b2ae35;
						hash2 ^= hash2 >> 16; hash2 *= 0x85ebca6b; hash2 ^= hash2 >> 13; hash2 *= 0xc2b2ae35;
						hash1 ^= hash2; hash1 ^= hash1 >> 16;
						prefix_tuple* _ptuple = &_tuple.ptuples[hash1 & _tuple.mask];
						while (_ptuple != NULL) {
							if (_ptuple->pri > res)break;
							// search in ptuple
							if (_prefix.i_64 == _ptuple->prefix.i_64) {
								// search in second layer
								if (!_ptuple->rules.empty()) {
									//for (auto& _r : _ptuple->rules) {
									for (int rid = 0; rid < _ptuple->rules.size(); ++rid) {
										++acc_r;
										auto& _r = _ptuple->rules[rid];
										if (res < _r.pri)break;
										if ((_r.ip.i_64 ^ _p.ip.i_64 & _r.mask.i_64) == 0 && (_r.protocol.val & _r.protocol.mask) == (_p.protocol & _r.protocol.mask) &&
											_r.Port[0][0] <= _p.Port[0] && _r.Port[0][1] >= _p.Port[0] &&
											_r.Port[1][0] <= _p.Port[1] && _r.Port[1][1] >= _p.Port[1]) {
											res = _r.pri;
											break;
										}
									}
								}
								// search in port_node
								for (int k = 0; k < 2; ++k) {
									if (_ptuple->pNodes[k] == NULL || _ptuple->pNodes[k]->pri > res)continue;
									uint32_t pn_id = _pext_u32(_p.Port[_ptuple->pNodes[k]->type], _ptuple->pNodes[k]->mask);
									if (res > _ptuple->pNodes[k]->buckets[pn_id].pri) {
										//for (auto& _r : _ptuple->pNodes[k]->buckets[pn_id].rules) {
										for (int rid = 0; rid < _ptuple->pNodes[k]->buckets[pn_id].rules.size(); ++rid) {
											++acc_r;
											auto& _r = _ptuple->pNodes[k]->buckets[pn_id].rules[rid];
											if (res < _r.pri)break;
											MASK _mask = { maskBit[_r.sip_length], maskBit[_r.dip_length] };
											if ((_r.ip.i_64 ^ _p.ip.i_64 & _r.mask.i_64) == 0 && (_r.protocol.val & _r.protocol.mask) == (_p.protocol & _r.protocol.mask) &&
												_r.Port[0][0] <= _p.Port[0] && _r.Port[0][1] >= _p.Port[0] &&
												_r.Port[1][0] <= _p.Port[1] && _r.Port[1][1] >= _p.Port[1]) {
												res = _r.pri;
												break;
											}
										}
									}
								}
								break;
							}
							_ptuple = _ptuple->next;
						}
					}
				}
			}
		}
		acc_bucket += acc_b;
		acc_tuple += acc_t;
		acc_rule += acc_r;
		if (max_bucket < acc_b)max_bucket = acc_b;
		if (max_tuple < acc_t)max_tuple = acc_t;
		if (max_rule < acc_r)max_rule = acc_r;
	}
	printf("\navg_acc_bucket: %f max: %d\n", (double)acc_bucket / (double)_packet.size(), max_bucket);
	printf("avg_acc_tuple: %f max: %d\n", (double)acc_tuple / (double)_packet.size(), max_tuple);
	printf("avg_acc_rule: %f max: %d\n", (double)acc_rule / (double)_packet.size(), max_rule);
}

void DBTable::insert(Rule& _r)
{
	MASK _mask = { maskBit[_r.sip_length], maskBit[_r.dip_length] };
	uint32_t idx = (_mask.i_64 & subsets.mask.i_64) == subsets.mask.i_64 ? _pext_u64(_r.ip.i_64 & _mask.i_64, subsets.mask.i_64) : (subsets.size - 1);
	if (subsets.ipNodes[idx].pri > _r.pri)subsets.ipNodes[idx].pri = _r.pri;
	// insert to tuple
	if (!subsets.ipNodes[idx].tuples.empty()) {
		MASK key = { maskBit[subsets.ipNodes[idx].prefix_down[_r.sip_length][_r.dip_length][0]], maskBit[subsets.ipNodes[idx].prefix_down[_r.sip_length][_r.dip_length][1]] };
		int i = 0;
		for (; i < subsets.ipNodes[idx].tuples.size(); ++i) {
			if (subsets.ipNodes[idx].tuples[i].key.i_64 == key.i_64) {
				break;
			}
		}
		if (i != subsets.ipNodes[idx].tuples.size()) {
			// add new tuple

			Tuple* _tuple = &subsets.ipNodes[idx].tuples[i];
			// expansion hashtable
			//if (_tuple->ptuple_num >= 0.75 * (_tuple->mask + 1)) {
			//	uint32_t new_mask = (_tuple->mask + 1) << 1;
			//	prefix_tuple* new_pTuples = new prefix_tuple[new_mask]();
			//	--new_mask;
			//	for (int j = 0; j < _tuple->mask + 1; ++j) {
			//		prefix_tuple* _tmp = &_tuple->ptuples[j];
			//		if (_tmp->pri != 0xFFFFFFFF) {
			//			uint32_t new_hash_id = hashCode(_tmp->prefix.i_32.sip, _tmp->prefix.i_32.dip) & new_mask;
			//			if (new_pTuples[new_hash_id].pri == 0xFFFFFFFF) {
			//				new_pTuples[new_hash_id] = *_tmp;
			//				//_tmp = _tmp->next;
			//				new_pTuples[new_hash_id].next = NULL;
			//			}
			//			else {
			//				prefix_tuple* iter1 = &new_pTuples[new_hash_id];
			//				prefix_tuple* iter2 = &new_pTuples[new_hash_id];
			//				while (iter2 != NULL) {
			//					if (_tmp->pri < iter2->pri)break;
			//					iter1 = iter2;
			//					iter2 = iter2->next;
			//				}
			//				prefix_tuple* _tmp1 = _tmp;
			//				//_tmp = _tmp->next;
			//				if (iter1 == iter2) {
			//					prefix_tuple* _tcopy = new prefix_tuple();
			//					*_tcopy = new_pTuples[new_hash_id];
			//					new_pTuples[new_hash_id] = *_tmp1;
			//					new_pTuples[new_hash_id].next = _tcopy;
			//				}
			//				else {
			//					prefix_tuple* _tcopy = new prefix_tuple();
			//					*_tcopy = *_tmp1;
			//					iter1->next = _tcopy;
			//					_tcopy->next = iter2;
			//				}
			//			}
			//		}
			//		_tmp = _tmp->next;
			//		while (_tmp != NULL) {
			//			uint32_t new_hash_id = hashCode(_tmp->prefix.i_32.sip, _tmp->prefix.i_32.dip) & new_mask;
			//			if (new_pTuples[new_hash_id].pri == 0xFFFFFFFF) {
			//				new_pTuples[new_hash_id] = *_tmp;
			//				new_pTuples[new_hash_id].next = NULL;
			//				prefix_tuple* del_pt = _tmp;
			//				_tmp = _tmp->next;
			//				delete del_pt;
			//			}
			//			else {
			//				prefix_tuple* iter1 = &new_pTuples[new_hash_id];
			//				prefix_tuple* iter2 = &new_pTuples[new_hash_id];
			//				while (iter2 != NULL) {
			//					if (_tmp->pri < iter2->pri)break;
			//					iter1 = iter2;
			//					iter2 = iter2->next;
			//				}
			//				prefix_tuple* _tmp1 = _tmp;
			//				_tmp = _tmp->next;
			//				if (iter1 == iter2) {
			//					prefix_tuple _tcopy = *_tmp1;
			//					*_tmp1 = new_pTuples[new_hash_id];
			//					new_pTuples[new_hash_id] = _tcopy;
			//					new_pTuples[new_hash_id].next = _tmp1;
			//				}
			//				else {
			//					iter1->next = _tmp1;
			//					_tmp1->next = iter2;
			//				}
			//			}
			//		}
			//	}
			//	delete[] _tuple->ptuples;
			//	_tuple->ptuples = new_pTuples;
			//	_tuple->mask = new_mask;
			//}
			// insert
			IP p_key = { _r.ip.i_64 & key.i_64 };
			uint32_t hash_idx = hashCode(p_key.i_32.sip, p_key.i_32.dip) & _tuple->mask;
			if (_tuple->ptuples[hash_idx].pri == 0xFFFFFFFF) {
				_tuple->ptuples[hash_idx].pri = _r.pri;
				_tuple->ptuples[hash_idx].prefix = p_key;
				_tuple->ptuples[hash_idx].rules.emplace_back(_r);
				++_tuple->ptuple_num;
			}
			else {
				prefix_tuple* _pTuple = &_tuple->ptuples[hash_idx];
				prefix_tuple* prior;
				while (_pTuple != NULL)
				{
					if (_pTuple->prefix.i_64 == p_key.i_64) {
						// if have port_node
						if (_pTuple->pNodes[1] != NULL && _r.Port[1][0] == _r.Port[1][1]) {
							int b_idx = _pext_u32(_r.Port[1][0], _pTuple->pNodes[1]->mask);
							if (_pTuple->pNodes[1]->buckets[b_idx].pri > _r.pri) {
								_pTuple->pNodes[1]->buckets[b_idx].pri = _r.pri;
							}
							int pri_idx = 0;
							for (; pri_idx < _pTuple->pNodes[1]->buckets[b_idx].rules.size(); ++pri_idx) {
								if (_pTuple->pNodes[1]->buckets[b_idx].rules[pri_idx].pri > _r.pri)break;
							}
							_pTuple->pNodes[1]->buckets[b_idx].rules.insert(_r, pri_idx);
							return;
						}
						else if (_pTuple->pNodes[0] != NULL && _r.Port[0][0] == _r.Port[0][1]) {
							int b_idx = _pext_u32(_r.Port[0][0], _pTuple->pNodes[0]->mask);
							if (_pTuple->pNodes[0]->buckets[b_idx].pri > _r.pri) {
								_pTuple->pNodes[0]->buckets[b_idx].pri = _r.pri;
							}
							int pri_idx = 0;
							for (; pri_idx < _pTuple->pNodes[0]->buckets[b_idx].rules.size(); ++pri_idx) {
								if (_pTuple->pNodes[0]->buckets[b_idx].rules[pri_idx].pri > _r.pri)break;
							}
							_pTuple->pNodes[0]->buckets[b_idx].rules.insert(_r, pri_idx);
							return;
						}
						else {
							int pri_idx = 0;
							for (; pri_idx < _pTuple->rules.size(); ++pri_idx) {
								if (_pTuple->rules[pri_idx].pri > _r.pri)break;
							}
							_pTuple->rules.insert(_r, pri_idx);
							return;
						}
					}
					prior = _pTuple;
					_pTuple = _pTuple->next;
				}
				if (_pTuple == NULL) {
					prefix_tuple* new_ptuple = new prefix_tuple();
					new_ptuple->pri = _r.pri;
					new_ptuple->prefix = p_key;
					new_ptuple->rules.emplace_back(_r);
					prior->next = new_ptuple;
					++_tuple->ptuple_num;
					return;
				}
			}
		}
		else {
			int pri_idx = 0;
			for (; pri_idx < subsets.ipNodes[idx].rules.size(); ++pri_idx) {
				if (subsets.ipNodes[idx].rules[pri_idx].pri > _r.pri)break;
			}
			subsets.ipNodes[idx].rules.insert(_r, pri_idx);
			return;
		}
	}
	else {
		int pri_idx = 0;
		for (; pri_idx < subsets.ipNodes[idx].rules.size(); ++pri_idx) {
			if (subsets.ipNodes[idx].rules[pri_idx].pri > _r.pri)break;
		}
		subsets.ipNodes[idx].rules.insert(_r, pri_idx);
		return;
	}
}

void DBTable::remove(Rule& _r)
{
	MASK _mask = { maskBit[_r.sip_length], maskBit[_r.dip_length] };
	uint32_t idx = (_mask.i_64 & subsets.mask.i_64) == subsets.mask.i_64 ? _pext_u64(_r.ip.i_64 & _mask.i_64, subsets.mask.i_64) : (subsets.size - 1);
	// search in tuple
	if (!subsets.ipNodes[idx].tuples.empty()) {
		MASK key = { maskBit[subsets.ipNodes[idx].prefix_down[_r.sip_length][_r.dip_length][0]], maskBit[subsets.ipNodes[idx].prefix_down[_r.sip_length][_r.dip_length][1]] };
		int i = 0;
		for (; i < subsets.ipNodes[idx].tuples.size(); ++i) {
			if (subsets.ipNodes[idx].tuples[i].key.i_64 == key.i_64) {
				break;
			}
		}
		if (i == subsets.ipNodes[idx].tuples.size()) {
			int pri_idx = 0;
			for (; pri_idx < subsets.ipNodes[idx].rules.size(); ++pri_idx) {
				if (subsets.ipNodes[idx].rules[pri_idx].pri == _r.pri)break;
			}
			if (pri_idx == subsets.ipNodes[idx].rules.size()) {
				printf("err-can not find rule in bucket.\n"); return;
			}
			subsets.ipNodes[idx].rules.remove(pri_idx);
			return;
		}
		else {
			Tuple* _tuple = &subsets.ipNodes[idx].tuples[i];
			// search
			IP p_key = { _r.ip.i_64 & key.i_64 };
			uint32_t hash_idx = hashCode(p_key.i_32.sip, p_key.i_32.dip) & _tuple->mask;
			if (_tuple->ptuples[hash_idx].pri == 0xFFFFFFFF) {
				printf("err-can not find ptuple.\n");
				return;
			}
			else {
				prefix_tuple* _pTuple = &_tuple->ptuples[hash_idx];
				prefix_tuple* prior;
				while (_pTuple != NULL)
				{
					if (_pTuple->prefix.i_64 == p_key.i_64) {
						// if have port_node
						if (_pTuple->pNodes[1] != NULL && _r.Port[1][0] == _r.Port[1][1]) {
							int b_idx = _pext_u32(_r.Port[1][0], _pTuple->pNodes[1]->mask);
							int pri_idx = 0;
							for (; pri_idx < _pTuple->pNodes[1]->buckets[b_idx].rules.size(); ++pri_idx) {
								if (_pTuple->pNodes[1]->buckets[b_idx].rules[pri_idx].pri == _r.pri)break;
							}
							if (pri_idx == _pTuple->pNodes[1]->buckets[b_idx].rules.size()) {
								printf("err-can not find rule in dport.\n"); return;
							}
							_pTuple->pNodes[1]->buckets[b_idx].rules.remove(pri_idx);
							return;
						}
						else if (_pTuple->pNodes[0] != NULL && _r.Port[0][0] == _r.Port[0][1]) {
							int b_idx = _pext_u32(_r.Port[0][0], _pTuple->pNodes[0]->mask);
							int pri_idx = 0;
							for (; pri_idx < _pTuple->pNodes[0]->buckets[b_idx].rules.size(); ++pri_idx) {
								if (_pTuple->pNodes[0]->buckets[b_idx].rules[pri_idx].pri == _r.pri)break;
							}
							if (pri_idx == _pTuple->pNodes[0]->buckets[b_idx].rules.size()) {
								printf("err-can not find rule in sport.\n"); return;
							}
							_pTuple->pNodes[0]->buckets[b_idx].rules.remove(pri_idx);
							return;
						}
						else {
							int pri_idx = 0;
							for (; pri_idx < _pTuple->rules.size(); ++pri_idx) {
								if (_pTuple->rules[pri_idx].pri == _r.pri)break;
							}
							if (pri_idx == _pTuple->rules.size()) {
								printf("err-can not find rule in ptuple.\n"); return;
							}
							_pTuple->rules.remove(pri_idx);
							return;
						}
					}
					prior = _pTuple;
					_pTuple = _pTuple->next;
				}
				if (_pTuple == NULL) {
					printf("err-can not find ptuple-2.\n");
					return;
				}
			}
		}
	}
	else {
		int pri_idx = 0;
		for (; pri_idx < subsets.ipNodes[idx].rules.size(); ++pri_idx) {
			if (subsets.ipNodes[idx].rules[pri_idx].pri == _r.pri)break;
		}
		if (pri_idx == subsets.ipNodes[idx].rules.size()) {
			printf("err-can not find rule in bucket.\n"); return;
		}
		subsets.ipNodes[idx].rules.remove(pri_idx);
	}
}

void DBTable::insert_multi_thread(Rule& _r)
{
	MASK _mask = { maskBit[_r.sip_length], maskBit[_r.dip_length] };
	uint32_t idx = (_mask.i_64 & subsets.mask.i_64) == subsets.mask.i_64 ? _pext_u64(_r.ip.i_64 & _mask.i_64, subsets.mask.i_64) : (subsets.size - 1);
	if (subsets.ipNodes[idx].pri > _r.pri)subsets.ipNodes[idx].pri = _r.pri;
	// insert to tuple
	if (!subsets.ipNodes[idx].tuples.empty()) {
		MASK key = { maskBit[subsets.ipNodes[idx].prefix_down[_r.sip_length][_r.dip_length][0]], maskBit[subsets.ipNodes[idx].prefix_down[_r.sip_length][_r.dip_length][1]] };
		int i = 0;
		for (; i < subsets.ipNodes[idx].tuples.size(); ++i) {
			if (subsets.ipNodes[idx].tuples[i].key.i_64 == key.i_64) {
				break;
			}
		}
		if (i == subsets.ipNodes[idx].tuples.size()) {
			// add new tuple
		}
		Tuple* _tuple = &subsets.ipNodes[idx].tuples[i];
		// expansion hashtable 
		//if (_tuple->ptuple_num >= 0.75 * (_tuple->mask + 1)) {
		//	uint32_t new_mask = (_tuple->mask + 1) << 1;
		//	prefix_tuple* new_pTuples = new prefix_tuple[new_mask]();
		//	--new_mask;
		//	for (int j = 0; j < _tuple->mask + 1; ++j) {
		//		prefix_tuple* _tmp = &_tuple->ptuples[j];
		//		if (_tmp->pri != 0xFFFFFFFF) {
		//			uint32_t new_hash_id = hashCode(_tmp->prefix.i_32.sip, _tmp->prefix.i_32.dip) & new_mask;
		//			if (new_pTuples[new_hash_id].pri == 0xFFFFFFFF) {
		//				new_pTuples[new_hash_id] = *_tmp;
		//				//_tmp = _tmp->next;
		//				new_pTuples[new_hash_id].next = NULL;
		//			}
		//			else {
		//				prefix_tuple* iter1 = &new_pTuples[new_hash_id];
		//				prefix_tuple* iter2 = &new_pTuples[new_hash_id];
		//				while (iter2 != NULL) {
		//					if (_tmp->pri < iter2->pri)break;
		//					iter1 = iter2;
		//					iter2 = iter2->next;
		//				}
		//				prefix_tuple* _tmp1 = _tmp;
		//				//_tmp = _tmp->next;
		//				if (iter1 == iter2) {
		//					prefix_tuple* _tcopy = new prefix_tuple();
		//					*_tcopy = new_pTuples[new_hash_id];
		//					new_pTuples[new_hash_id] = *_tmp1;
		//					new_pTuples[new_hash_id].next = _tcopy;
		//				}
		//				else {
		//					prefix_tuple* _tcopy = new prefix_tuple();
		//					*_tcopy = *_tmp1;
		//					iter1->next = _tcopy;
		//					_tcopy->next = iter2;
		//				}
		//			}
		//		}
		//		_tmp = _tmp->next;
		//		while (_tmp != NULL) {
		//			uint32_t new_hash_id = hashCode(_tmp->prefix.i_32.sip, _tmp->prefix.i_32.dip) & new_mask;
		//			if (new_pTuples[new_hash_id].pri == 0xFFFFFFFF) {
		//				new_pTuples[new_hash_id] = *_tmp;
		//				new_pTuples[new_hash_id].next = NULL;
		//				//prefix_tuple* del_pt = _tmp;
		//				_tmp = _tmp->next;
		//				//delete del_pt;
		//			}
		//			else {
		//				prefix_tuple* iter1 = &new_pTuples[new_hash_id];
		//				prefix_tuple* iter2 = &new_pTuples[new_hash_id];
		//				while (iter2 != NULL) {
		//					if (_tmp->pri < iter2->pri)break;
		//					iter1 = iter2;
		//					iter2 = iter2->next;
		//				}
		//				prefix_tuple* _tmp1 = _tmp;
		//				_tmp = _tmp->next;
		//				if (iter1 == iter2) {
		//					prefix_tuple* _tcopy = new prefix_tuple();
		//					*_tcopy = new_pTuples[new_hash_id];
		//					new_pTuples[new_hash_id] = *_tmp1;
		//					new_pTuples[new_hash_id].next = _tcopy;
		//				}
		//				else {
		//					prefix_tuple* _tcopy = new prefix_tuple();
		//					*_tcopy = *_tmp1;
		//					iter1->next = _tcopy;
		//					_tcopy->next = iter2;
		//				}
		//			}
		//		}
		//	}
		//	//delete[] _tuple->ptuples;
		//	_tuple->ptuples = new_pTuples;
		//	_tuple->mask = new_mask;
		//}
		// insert
		IP p_key = { _r.ip.i_64 & key.i_64 };

		uint32_t hash1 = p_key.i_32.sip;
		uint32_t hash2 = p_key.i_32.dip;
		hash1 ^= hash1 >> 16; hash1 *= 0x85ebca6b; hash1 ^= hash1 >> 13; hash1 *= 0xc2b2ae35;
		hash2 ^= hash2 >> 16; hash2 *= 0x85ebca6b; hash2 ^= hash2 >> 13; hash2 *= 0xc2b2ae35;
		hash1 ^= hash2; hash1 ^= hash1 >> 16;
		prefix_tuple* _pTuple = &_tuple->ptuples[hash1 & _tuple->mask];

		//uint32_t idx = hashCode(p_key.i_32.sip, p_key.i_32.dip) & _tuple->mask;


		if (_pTuple->pri == 0xFFFFFFFF) {
			_pTuple->pri = _r.pri;
			_pTuple->prefix = p_key;
			_pTuple->rules.emplace_back(_r);
			++_tuple->ptuple_num;
		}
		else {
			//prefix_tuple* _pTuple = &_tuple->ptuples[idx];
			prefix_tuple* prior;
			while (_pTuple != NULL)
			{
				if (_pTuple->prefix.i_64 == p_key.i_64) {
					// if have port_node
					if (_pTuple->pNodes[1] != NULL && _r.Port[1][0] == _r.Port[1][1]) {
						int b_idx = _pext_u32(_r.Port[1][0], _pTuple->pNodes[1]->mask);
						if (_pTuple->pNodes[1]->buckets[b_idx].pri > _r.pri) {
							_pTuple->pNodes[1]->buckets[b_idx].pri = _r.pri;
						}
						int pri_idx = 0;
						for (; pri_idx < _pTuple->pNodes[1]->buckets[b_idx].rules.size(); ++pri_idx) {
							if (_pTuple->pNodes[1]->buckets[b_idx].rules[pri_idx].pri > _r.pri)break;
						}
						_pTuple->pNodes[1]->buckets[b_idx].rules.insert_recycle(_r, pri_idx);
						return;
					}
					else if (_pTuple->pNodes[0] != NULL && _r.Port[0][0] == _r.Port[0][1]) {
						int b_idx = _pext_u32(_r.Port[0][0], _pTuple->pNodes[0]->mask);
						if (_pTuple->pNodes[0]->buckets[b_idx].pri > _r.pri) {
							_pTuple->pNodes[0]->buckets[b_idx].pri = _r.pri;
						}
						int pri_idx = 0;
						for (; pri_idx < _pTuple->pNodes[0]->buckets[b_idx].rules.size(); ++pri_idx) {
							if (_pTuple->pNodes[0]->buckets[b_idx].rules[pri_idx].pri > _r.pri)break;
						}
						_pTuple->pNodes[0]->buckets[b_idx].rules.insert_recycle(_r, pri_idx);
						return;
					}
					else {
						int pri_idx = 0;
						for (; pri_idx < _pTuple->rules.size(); ++pri_idx) {
							if (_pTuple->rules[pri_idx].pri > _r.pri)break;
						}
						_pTuple->rules.insert_recycle(_r, pri_idx);
						return;
					}
				}
				prior = _pTuple;
				_pTuple = _pTuple->next;
			}
			if (_pTuple == NULL) {
				prefix_tuple* new_ptuple = new prefix_tuple();
				new_ptuple->pri = _r.pri;
				new_ptuple->prefix = p_key;
				new_ptuple->rules.emplace_back(_r);
				prior->next = new_ptuple;
				++_tuple->ptuple_num;
				return;
			}
		}
	}
	else {
		int pri_idx = 0;
		for (; pri_idx < subsets.ipNodes[idx].rules.size(); ++pri_idx) {
			if (subsets.ipNodes[idx].rules[pri_idx].pri > _r.pri)break;
		}
		subsets.ipNodes[idx].rules.insert_recycle(_r, pri_idx);
		return;
	}
}

void DBTable::remove_multi_thread(Rule& _r)
{
	MASK _mask = { maskBit[_r.sip_length], maskBit[_r.dip_length] };
	uint32_t idx = (_mask.i_64 & subsets.mask.i_64) == subsets.mask.i_64 ? _pext_u64(_r.ip.i_64 & _mask.i_64, subsets.mask.i_64) : (subsets.size - 1);
	// search in tuple
	if (!subsets.ipNodes[idx].tuples.empty()) {
		MASK key = { maskBit[subsets.ipNodes[idx].prefix_down[_r.sip_length][_r.dip_length][0]], maskBit[subsets.ipNodes[idx].prefix_down[_r.sip_length][_r.dip_length][1]] };
		int i = 0;
		for (; i < subsets.ipNodes[idx].tuples.size(); ++i) {
			if (subsets.ipNodes[idx].tuples[i].key.i_64 == key.i_64) {
				break;
			}
		}
		if (i == subsets.ipNodes[idx].tuples.size()) {
			// 
			printf("err-can not find rule.");
			return;
		}
		Tuple* _tuple = &subsets.ipNodes[idx].tuples[i];
		// search
		IP p_key = { _r.ip.i_64 & key.i_64 };

		uint32_t hash1 = p_key.i_32.sip;
		uint32_t hash2 = p_key.i_32.dip;
		hash1 ^= hash1 >> 16; hash1 *= 0x85ebca6b; hash1 ^= hash1 >> 13; hash1 *= 0xc2b2ae35;
		hash2 ^= hash2 >> 16; hash2 *= 0x85ebca6b; hash2 ^= hash2 >> 13; hash2 *= 0xc2b2ae35;
		hash1 ^= hash2; hash1 ^= hash1 >> 16;
		prefix_tuple* _pTuple = &_tuple->ptuples[hash1 & _tuple->mask];

		//uint32_t idx = hashCode(p_key.i_32.sip, p_key.i_32.dip) & _tuple->mask;
		if (_pTuple->pri == 0xFFFFFFFF) {
			printf("err-can not find rule.");
			return;
		}
		else {
			//prefix_tuple* _pTuple = &_tuple->ptuples[idx];
			prefix_tuple* prior;
			while (_pTuple != NULL)
			{
				if (_pTuple->prefix.i_64 == p_key.i_64) {
					// if have port_node
					if (_pTuple->pNodes[1] != NULL && _r.Port[1][0] == _r.Port[1][1]) {
						int b_idx = _pext_u32(_r.Port[1][0], _pTuple->pNodes[1]->mask);
						int pri_idx = 0;
						for (; pri_idx < _pTuple->pNodes[1]->buckets[b_idx].rules.size(); ++pri_idx) {
							if (_pTuple->pNodes[1]->buckets[b_idx].rules[pri_idx].pri == _r.pri)break;
						}
						if (pri_idx == _pTuple->pNodes[1]->buckets[b_idx].rules.size()) {
							printf("err-can not find rule."); return;
						}
						_pTuple->pNodes[1]->buckets[b_idx].rules.remove_recycle(pri_idx);
						return;
					}
					else if (_pTuple->pNodes[0] != NULL && _r.Port[0][0] == _r.Port[0][1]) {
						int b_idx = _pext_u32(_r.Port[0][0], _pTuple->pNodes[0]->mask);
						int pri_idx = 0;
						for (; pri_idx < _pTuple->pNodes[0]->buckets[b_idx].rules.size(); ++pri_idx) {
							if (_pTuple->pNodes[0]->buckets[b_idx].rules[pri_idx].pri == _r.pri)break;
						}
						if (pri_idx == _pTuple->pNodes[0]->buckets[b_idx].rules.size()) {
							printf("err-can not find rule."); return;
						}
						_pTuple->pNodes[0]->buckets[b_idx].rules.remove_recycle(pri_idx);
						return;
					}
					else {
						int pri_idx = 0;
						for (; pri_idx < _pTuple->rules.size(); ++pri_idx) {
							if (_pTuple->rules[pri_idx].pri == _r.pri)break;
						}
						if (pri_idx == _pTuple->rules.size()) {
							printf("err-can not find rule."); return;
						}
						_pTuple->rules.remove_recycle(pri_idx);
						return;
					}
				}
				prior = _pTuple;
				_pTuple = _pTuple->next;
			}
			if (_pTuple == NULL) {
				printf("err-can not find rule.");
				return;
			}
		}
	}
	else {
		int pri_idx = 0;
		for (; pri_idx < subsets.ipNodes[idx].rules.size(); ++pri_idx) {
			if (subsets.ipNodes[idx].rules[pri_idx].pri == _r.pri)break;
		}
		if (pri_idx == subsets.ipNodes[idx].rules.size()) {
			printf("err-can not find rule."); return;
		}
		subsets.ipNodes[idx].rules.remove_recycle(pri_idx);
		return;
	}
}

void DBTable::print_nodes()
{
	FILE* fp = NULL;
	fp = fopen("nodes.txt", "w");
	if (fp == NULL) {
		fprintf(stderr, "error - can not creat nodes.txt\n");
		return;
	}
	fprintf(fp, "Nodes Information [SID SIZE SIG PN_SIZE PT_SIZE]  (SIG={[0, 0], (0, 10], (10, 50], (50, 100], (100, +)})\n");
	fprintf(fp, "                  |- RULE\n");
	fprintf(fp, "                  |- ...\n");

	int bound_1 = 11;
	int bound_2 = 51;
	int bound_3 = 101;
	bool have_false = false;

	int target_bucket_num = 0;
	int max_bucket_size = 0;
	int small_bucket = 0;
	int mid_bucket = 0;
	int big_bucket = 0;
	int total_bucket_num = 0;
	int used_bucket_num = 0;
	int used_tuple_space = 0;
	int used_tuple = 0;
	int max_tuples = 0;
	uint32_t rule_num = 0;
	uint32_t rule_num_in_bucket = 0;

	total_bucket_num = subsets.nodes_num;
	for (size_t i = 0; i < subsets.nodes_num; ++i) {
		if (subsets.ipNodes[i].pri != 0xFFFFFFFF) {
			++used_bucket_num;
			int _bucket_size;
			if (!subsets.ipNodes[i].rules.empty()) {
				_bucket_size = subsets.ipNodes[i].rules.size();
				fprintf(fp, "\nSIZE= %d ", _bucket_size);
				if (_bucket_size < threshold)++target_bucket_num;
				if (_bucket_size > max_bucket_size)max_bucket_size = _bucket_size;
				if (_bucket_size < bound_1) {
					fprintf(fp, "(0, 10]\n");
				}
				else if (_bucket_size < bound_2) {
					fprintf(fp, "(10, 50]\n");
					++small_bucket;
				}
				else if (_bucket_size < bound_3) {
					fprintf(fp, "(50, 100]\n");
					++mid_bucket;
				}
				else {
					fprintf(fp, "(100, +)\n");
					++big_bucket;
				}
				rule_num += subsets.ipNodes[i].rules.size();
				rule_num_in_bucket += subsets.ipNodes[i].rules.size();
				//for (auto& _r : subsets.ipNodes[i].rules) {
				for (int rid = 0; rid < subsets.ipNodes[i].rules.size(); ++rid) {
					auto& _r = subsets.ipNodes[i].rules[rid];
					fprintf(fp, "|- %u\t%u.%u.%u.%u/%u\t\t%u.%u.%u.%u/%u\t\t%u:%u\t\t%u:%u\t\t%u\n", _r.pri, _r.ip.i_8.sip[3], _r.ip.i_8.sip[2], _r.ip.i_8.sip[1],
						_r.ip.i_8.sip[0], _r.sip_length, _r.ip.i_8.dip[3], _r.ip.i_8.dip[2], _r.ip.i_8.dip[1], _r.ip.i_8.dip[0], _r.dip_length,
						_r.Port[0][0], _r.Port[0][1], _r.Port[1][0], _r.Port[1][1], _r.protocol.val);
				}
			}
			if (!subsets.ipNodes[i].tuples.empty()) {
				++used_tuple_space;
				used_tuple += subsets.ipNodes[i].tuples.size();
				if (subsets.ipNodes[i].tuples.size() > max_tuples)max_tuples = subsets.ipNodes[i].tuples.size();
				fprintf(fp, "\nUSED_TUPLES %d", subsets.ipNodes[i].tuples.size());
				for (auto& _tuple : subsets.ipNodes[i].tuples) {
					total_bucket_num += _tuple.mask + 1;
					used_bucket_num += _tuple.ptuple_num;
					for (int j = 0; j < _tuple.mask + 1; ++j) {
						prefix_tuple* _ptuple = &_tuple.ptuples[j];
						while (_ptuple != NULL && _ptuple->pri != 0xFFFFFFFF) {
							if (!_ptuple->rules.empty()) {
								_bucket_size = _ptuple->rules.size();
								bitset<32> bits;
								bits = _tuple.key.i_32.smask;
								int tu_1 = bits.count();
								bits = _tuple.key.i_32.dmask;
								int tu_2 = bits.count();
								fprintf(fp, "\nPT_SIZE= %d TUPLE (%d,%d) HASH %d ", _bucket_size, tu_1, tu_2, j);
								if (_bucket_size < threshold)++target_bucket_num;
								if (_bucket_size > max_bucket_size)max_bucket_size = _bucket_size;
								if (_bucket_size < bound_1) {
									fprintf(fp, "(0, 10]\n");
								}
								else if (_bucket_size < bound_2) {
									fprintf(fp, "(10, 50]\n");
									++small_bucket;
								}
								else if (_bucket_size < bound_3) {
									fprintf(fp, "(50, 100]\n");
									++mid_bucket;
								}
								else {
									fprintf(fp, "(100, +)\n");
									++big_bucket;
								}
								rule_num += _ptuple->rules.size();
								//for (auto& _r : _ptuple->rules) {
								for (int rid = 0; rid < _ptuple->rules.size(); ++rid) {
									auto& _r = _ptuple->rules[rid];
									fprintf(fp, "|- %u\t%u.%u.%u.%u/%u\t\t%u.%u.%u.%u/%u\t\t%u:%u\t\t%u:%u\t\t%u\n", _r.pri, _r.ip.i_8.sip[3], _r.ip.i_8.sip[2], _r.ip.i_8.sip[1],
										_r.ip.i_8.sip[0], _r.sip_length, _r.ip.i_8.dip[3], _r.ip.i_8.dip[2], _r.ip.i_8.dip[1], _r.ip.i_8.dip[0], _r.dip_length,
										_r.Port[0][0], _r.Port[0][1], _r.Port[1][0], _r.Port[1][1], _r.protocol.val);
								}
							}
							for (int k = 0; k < 2; ++k) {
								if (_ptuple->pNodes[k] != NULL) {
									port_node* p_node = _ptuple->pNodes[k];
									bitset<16> bits = p_node->mask;
									int pn_size = 1 << bits.count();
									total_bucket_num += pn_size;
									for (int v = 0; v < pn_size; ++v) {
										if (p_node->buckets[v].pri != 0xFFFFFFFF) {
											++used_bucket_num;
											_bucket_size = p_node->buckets[v].rules.size();
											fprintf(fp, "\nPN_SIZE= %d ", _bucket_size);
											if (_bucket_size < threshold)++target_bucket_num;
											if (_bucket_size > max_bucket_size)max_bucket_size = _bucket_size;
											if (_bucket_size < bound_1) {
												fprintf(fp, "(0, 10]\n");
											}
											else if (_bucket_size < bound_2) {
												fprintf(fp, "(10, 50]\n");
												++small_bucket;
											}
											else if (_bucket_size < bound_3) {
												fprintf(fp, "(50, 100]\n");
												++mid_bucket;
											}
											else {
												fprintf(fp, "(100, +)\n");
												++big_bucket;
											}
											rule_num += p_node->buckets[v].rules.size();
											//for (auto& _r : p_node->buckets[v].rules) {
											for (int rid = 0; rid < p_node->buckets[v].rules.size(); ++rid) {
												auto& _r = p_node->buckets[v].rules[rid];
												fprintf(fp, "|- %u\t%u.%u.%u.%u/%u\t\t%u.%u.%u.%u/%u\t\t%u:%u\t\t%u:%u\t\t%u\n", _r.pri, _r.ip.i_8.sip[3], _r.ip.i_8.sip[2], _r.ip.i_8.sip[1],
													_r.ip.i_8.sip[0], _r.sip_length, _r.ip.i_8.dip[3], _r.ip.i_8.dip[2], _r.ip.i_8.dip[1], _r.ip.i_8.dip[0], _r.dip_length,
													_r.Port[0][0], _r.Port[0][1], _r.Port[1][0], _r.Port[1][1], _r.protocol.val);
											}
										}
									}

								}
							}
							_ptuple = _ptuple->next;
						}
					}
				}
			}
		}
	}
	printf("rule_num %d %d\n", rule_num, ruleset.size());
	printf("in_bucket %d %f\n", rule_num_in_bucket, (double)rule_num_in_bucket / ruleset.size());
	printf("in_tuple %d %f\n", rule_num - rule_num_in_bucket, (double)(rule_num - rule_num_in_bucket) / ruleset.size());
	printf("total buckets  : %d\n", total_bucket_num);
	printf("used buckets   : %d %f\%\n", used_bucket_num, (double)used_bucket_num / (double)total_bucket_num * 100);
	printf("max bucket size: %d\n", max_bucket_size);
	printf("target buckets : %d %f\%\n", target_bucket_num, (double)target_bucket_num / (double)used_bucket_num * 100);
	printf("(10,50]        : %d %f\%\n", small_bucket, (double)small_bucket / (double)used_bucket_num * 100);
	printf("(50,100]       : %d %f\%\n", mid_bucket, (double)mid_bucket / (double)used_bucket_num * 100);
	printf("big cell       : %d %f\%\n", big_bucket, (double)big_bucket / (double)used_bucket_num * 100);
	printf("tuple spaces   : %d\n", used_tuple_space);
	printf("avg tuples     : %f\n", (double)used_tuple / (double)used_tuple_space);
	printf("max tuples     : %d\n\n", max_tuples);
	fclose(fp);
}

void DBTable::mem()
{
	size_t mem = sizeof(SubSet) + subsets.size * sizeof(ip_node);
	for (int i = 0; i < subsets.size; ++i) {
		if (subsets.ipNodes[i].pri != 0xFFFFFFFF) {
			//mem += (subsets.ipNodes[i].rules.size() * sizeof(Rule) + subsets.ipNodes[i].tuples.size() * sizeof(Tuple));
			mem += (subsets.ipNodes[i].tuples.size() * sizeof(Tuple));
			for (auto& _tuple : subsets.ipNodes[i].tuples) {
				mem += tuple_mem(_tuple);
			}
		}
		if (subsets.ipNodes[i].prefix_down != NULL)mem += (2178 * sizeof(char));
	}
	printf("\nTotal memory %f MB\n", mem / 1048676.0);
}

size_t DBTable::tuple_mem(Tuple& _tuple)
{
	size_t mem = 0;
	for (int i = 0; i < (_tuple.mask + 1); ++i) {
		if (_tuple.ptuples[i].pri != 0xFFFFFFFF) {
			mem += ptule_mem(_tuple.ptuples[i]);
		}
		else
		{
			mem += sizeof(prefix_tuple);
		}
	}
	return mem;
}

size_t DBTable::ptule_mem(prefix_tuple& _ptuple)
{
	prefix_tuple* _p = &_ptuple;
	size_t mem = 0;
	while (_p != NULL) {
		//mem += (sizeof(prefix_tuple) + _ptuple.rules.size() * sizeof(Rule));
		mem += (sizeof(prefix_tuple));
		for (int i = 0; i < 2; ++i) {
			if (_p->pNodes[i] != NULL)mem += portNode_mem(_p->pNodes[i]);
		}
		_p = _p->next;
	}
	return mem;
}

size_t DBTable::portNode_mem(port_node* _pnode)
{
	bitset<16> bits = _pnode->mask;
	int pn_size = 1 << bits.count();
	size_t mem = sizeof(port_node) + pn_size * sizeof(Bucket);
	/*for (int i = 0; i < pn_size; ++i) {
		mem += (_pnode->buckets[i].rules.size() * sizeof(Rule));
	}*/
	return mem;
}
