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


#include "method.h"


void single_thread(bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list)
{
	struct timespec t1, t2;
	cout << "\nbuild for single thread...\n";
	cout << "binth=" << BINTH << " th_b=" << END_BOUND << " K=" << TOP_K << " th_c=" << C_BOUND << endl << endl;
	
	DBTable dbt(rules, BINTH);
	clock_gettime(CLOCK_REALTIME, &t1);
	dbt.construct();
	clock_gettime(CLOCK_REALTIME, &t2);
	cout << "Construction Time: " << get_milli_time(&t1, &t2) << " ms\n";

	dbt.mem();

	cout << "\nstart search...\n";
	uint32_t res = 0;
	//FILE* res_fp = NULL;
	//res_fp = fopen("results.txt", "w");
	double search_time = 0;
	clock_gettime(CLOCK_REALTIME, &t1);
	//uint32_t _start = GetCPUCycle();
	for (int i = 0; i < packets.size(); ++i) {
		/*if (i == 2)
			printf("%d\n", i);*/
			//clock_gettime(CLOCK_REALTIME, &t1);
		res = dbt.search(packets[i]);
		//clock_gettime(CLOCK_REALTIME, &t2);
		//double _time = get_nano_time(&t1, &t2);
		//search_time += _time;
		/*if (res != check_list[i]) {
			if (res > check_list[i] && !check_correct(rules[res], packets[i])) {
				fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but return %d.", i, check_list[i], res);
				return -1;
			}
		}*/
		//int true_result = simple_search(rules, packets[i]);
		//if (res != true_result) {
		//	fprintf(stderr, "packet %d search result is uncorrect! true is %d, but result %d.\n", i, true_result, res);
		//	//return -1;
		//}
		//fprintf(res_fp, "Packet %d \t Result %d \t Time(um) %f\n", i, res, _time / 1000.0);
	}
	clock_gettime(CLOCK_REALTIME, &t2);
	//uint32_t _end = GetCPUCycle();
	//search_time = _end - _start;
	search_time = get_nano_time(&t1, &t2);
	//fclose(res_fp);
	cout << "|- Average search time: " << search_time / packets.size() / 1000.0 << "us\n";
	//cout << "|- Average search cycle: " << search_time / packets.size() << "\n\n";

	dbt.search_with_log(packets);


	// update
	int update_num = 5000;
	cout << "\nStart update...\n";
	random_device seed;
	mt19937 rd(seed());
	uniform_int_distribution<> dis(0, rules.size() * 0.6);
	double update_time = 0;

	for (int i = 0; i < update_num; ++i) {
		int cur_idx = dis(rd);
		clock_gettime(CLOCK_REALTIME, &t1);
		dbt.remove(rules[cur_idx]);
		dbt.insert(rules[cur_idx]);
		clock_gettime(CLOCK_REALTIME, &t2);
		update_time += get_nano_time(&t1, &t2);
	}
	cout << "|- Average update time: " << update_time / (update_num * 2) / 1000.0 << "us\n\n";
}

void multi_thread(bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list, int thread_num)
{
	cout << "\nbuild for multi-thread...\n";

	DBTable dbt(rules, 4);
	dbt.construct();

	//random_device seed;
	//mt19937 rd(seed());
	//uniform_int_distribution<> dis(0, rules.size() * 0.7);
	srand(20);
	int rule_range = rules.size() * 0.5;
	int up_num[4] = { 5, 50, 500, 5000 };
	vector<int> up_idx[4];
	chrono::milliseconds up_step[4];
	up_step[0] = chrono::milliseconds(1000);
	up_step[1] = chrono::milliseconds(100);
	up_step[2] = chrono::milliseconds(10);
	up_step[3] = chrono::milliseconds(1);
	for (int i = 0; i < 4; ++i) {
		for (int k = 0; k < up_num[i]; ++k)up_idx[i].emplace_back(rand() % rule_range);
	}

	double throughput[32];
	atomic_bool start_test(false);
	thread threads[32];

	//int thread_num = 1;
	//for (; thread_num <= 32; thread_num *= 2) {
		start_test = false;
		// multi-thread read with write
		thread update_thread([&]()-> bool {
			struct timespec t1, t2;
			double s_time = 0;

			while (!start_test);

			for (int i = 0; i < 4; ++i) {
				for (int k = 0; k < up_num[i]; ++k) {
					clock_gettime(CLOCK_REALTIME, &t1);
					dbt.remove_multi_thread(rules[up_idx[i][k]]);
					dbt.insert_multi_thread(rules[up_idx[i][k]]);
					clock_gettime(CLOCK_REALTIME, &t2);
					s_time += get_nano_time(&t1, &t2);
					this_thread::sleep_for(up_step[i]);
				}
			}

			printf("\nupdate num --- stage1: %d stage2: %d stage3: %d stage4: %d\n", up_num[0], up_num[1], up_num[2], up_num[3]);
			int total_upNum = (up_num[0] + up_num[1] + up_num[2] + up_num[3]) * 2;
			printf("total operate num: %d avg update time: %f um throughput: %f M/s\n", total_upNum, s_time / total_upNum / 1000.0, 1000.0 * total_upNum / s_time);

			this_thread::sleep_for(chrono::seconds(5));
			start_test = false;

			return true;
			});


		for (int i = 0; i < thread_num; ++i) {
			threads[i] = thread([&](int id)->bool
				{
					struct timespec t1, t2;
					double s_time = 0;
					uint64_t p_num = 0;
					int res;
					while (!start_test);

					while (start_test) {
						//printf("%d\n", j);
						clock_gettime(CLOCK_REALTIME, &t1);
						for (int p_id = 0; p_id < packets.size(); ++p_id) {
							//clock_gettime(CLOCK_REALTIME, &t1);
							res = dbt.search(packets[p_id]);
							//clock_gettime(CLOCK_REALTIME, &t2);
							//double _time = get_nano_time(&t1, &t2);
							//printf("%f\n", _time);
							//s_time += _time;
							//if (res != -1 && res != check_list[p_id]) {
							//	if (!check_correct(rules[res], packets[p_id])) {
							//		fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but return %d.", p_id, check_list[p_id], res);
							//		//printf("Packet %d search result is uncorrect! True is %d, but return %d.", j, check_list[j], res);
							//		//return false;
							//	}
							//}
						}
						clock_gettime(CLOCK_REALTIME, &t2);
						s_time += get_nano_time(&t1, &t2);
						p_num += packets.size();
					}


					throughput[id] = 1000.0 * p_num / s_time;
					//printf("%d %d %f\n", start_p, end_p, s_time / (end_p - start_p) / 1000.0);
					//printf("id: %d throughput: %f\n", id, s_time / (end_p - start_p) / 1000.0);
					return true;
				}, i);
		}

		start_test = true;
		double total_throughput = 0;
		update_thread.join();
		for (int i = 0; i < thread_num; ++i) {
			threads[i].join();
			total_throughput += throughput[i];
		}

		printf("\n%d thread throughput with update: %f M/s\navg search time %f um\n", thread_num, total_throughput, thread_num / total_throughput);


		// multi-thread read
		start_test = false;
		for (int i = 0; i < thread_num; ++i) {
			threads[i] = thread([&](int id)->bool
				{
					struct timespec t1, t2;
					double s_time = 0;
					uint32_t p_num = 0;
					int res;
					while (!start_test);

					while (start_test) {
						//printf("%d\n", j);
						clock_gettime(CLOCK_REALTIME, &t1);
						for (int p_id = 0; p_id < packets.size(); ++p_id) {
							//clock_gettime(CLOCK_REALTIME, &t1);
							res = dbt.search(packets[p_id]);
							//clock_gettime(CLOCK_REALTIME, &t2);
							//double _time = get_nano_time(&t1, &t2);
							//printf("%f\n", _time);
							//s_time += _time;
							//if (res != -1 && res != check_list[p_id]) {
							//	if (!check_correct(rules[res], packets[p_id])) {
							//		fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but return %d.", p_id, check_list[p_id], res);
							//		//printf("Packet %d search result is uncorrect! True is %d, but return %d.", j, check_list[j], res);
							//		//return false;
							//	}
							//}
						}
						clock_gettime(CLOCK_REALTIME, &t2);
						s_time += get_nano_time(&t1, &t2);
						p_num += packets.size();
					}


					throughput[id] = 1000.0 * p_num / s_time;
					//printf("%d %d %f\n", start_p, end_p, s_time / (end_p - start_p) / 1000.0);
					//printf("id: %d throughput: %f\n", id, s_time / (end_p - start_p) / 1000.0);
					return true;
				}, i);
		}

		start_test = true;
		sleep(35);
		start_test = false;
		total_throughput = 0;
		for (int i = 0; i < thread_num; ++i) {
			threads[i].join();
			total_throughput += throughput[i];
		}
		printf("\n%d thread throughput: %f M/s\navg search time %f um\n", thread_num, total_throughput, thread_num / total_throughput);

	//}
}

void shif_rulesets()
{
	vector<vector<Rule>> rulesets;
	vector<Packet> packets;
	vector<Rule*> rules;
	rulesets.resize(6);
	packets.resize(1000000);
	/*char* file_names[6] = { "../../../ACL_dataset/acl1_256k.txt",
							"../../../ACL_dataset/acl2_256k.txt" ,
							"../../../ACL_dataset/acl3_256k.txt" ,
							"../../../ACL_dataset/acl4_256k.txt" ,
							"../../../ACL_dataset/acl5_256k.txt",
							"../../../ACL_dataset/acl1_256k.txt" };*/
	/*char* file_names[6] = { "../../../ACL_dataset/fw1_256k.txt",
							"../../../ACL_dataset/fw2_256k.txt" ,
							"../../../ACL_dataset/fw3_256k.txt" ,
							"../../../ACL_dataset/fw4_256k.txt" ,
							"../../../ACL_dataset/fw5_256k.txt",
							"../../../ACL_dataset/fw1_256k.txt" };*/
	char* file_names[2] = { "../../../ACL_dataset/ipc1_256k.txt",
							"../../../ACL_dataset/ipc2_256k.txt" };
	for (int i = 0; i < 2; ++i) {
		read_rules(file_names[i], rulesets[i]);
	}
	for (auto& _r : rulesets[0])rules.emplace_back(&_r);
	int shift_num = 20000;
	/*int insert_pri = rules.size() - 1000;
	for (int i = 0; i < 1000; ++i) {
		rules[rules.size() - i - 1]->pri = 0xFFFFFFFE - i;
	}*/
	gen_trace(packets, rules, 1000000);
	DBTable dbt(rules, 4);
	dbt.construct();

	random_device seed;
	mt19937 rd(seed());
	uniform_int_distribution<> dis(0, rules.size() * 0.8);
	double search_time = 0;
	struct timespec t1, t2;
	uint32_t res = 0;
	clock_gettime(CLOCK_REALTIME, &t1);
	for (int i = 0; i < packets.size(); ++i) {
		res = dbt.search(packets[i]);
	}
	clock_gettime(CLOCK_REALTIME, &t2);
	search_time = get_nano_time(&t1, &t2);
	cout << "|- Average search time 0: " << search_time / packets.size() / 1000.0 << "us\n\n";

	for (int i = 1; i < 2; ++i) {
		uniform_int_distribution<> _dis(0, rulesets[i].size() * 0.2);
		vector<int> temp1, temp2;
		for (int j = 0; j < shift_num; ++j) {
			int _re = dis(rd);
			while (find(temp1.begin(), temp1.end(), _re) != temp1.end()) { _re = dis(rd); }
			temp1.emplace_back(_re);
			int _in = _dis(rd);
			while (find(temp2.begin(), temp2.end(), _in) != temp2.end()) { _in = _dis(rd); }
			temp2.emplace_back(_in);
			dbt.remove(*(rules[_re]));
			rules[_re] = &rulesets[i][_in];
			rulesets[i][_in].pri = _re;
			dbt.insert(rulesets[i][_in]);
		}
		gen_trace(packets, rules, 1000000);
		clock_gettime(CLOCK_REALTIME, &t1);
		for (int i = 0; i < packets.size(); ++i) {
			res = dbt.search(packets[i]);
		}
		clock_gettime(CLOCK_REALTIME, &t2);
		search_time = get_nano_time(&t1, &t2);
		cout << "|- Average search time " << i << " : " << search_time / packets.size() / 1000.0 << "um\n\n";
	}
}

void single_thread_cycle(bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list)
{
	struct timespec t1, t2;
	cout << "\nbuild for single thread...\n";

	DBTable dbt(rules, 4);
	dbt.construct();
	//dbt.mem();

	cout << "\nstart search...\n";
	uint32_t res = 0;
	//FILE* res_fp = NULL;
	//res_fp = fopen("results.txt", "w");
	double search_time = 0;
	//clock_gettime(CLOCK_REALTIME, &t1);
	uint64_t _start = GetCPUCycle();
	for (int i = 0; i < packets.size(); ++i) {
		/*if (i == 2)
			printf("%d\n", i);*/
			//clock_gettime(CLOCK_REALTIME, &t1);
		res = dbt.search(packets[i]);
		//clock_gettime(CLOCK_REALTIME, &t2);
		//double _time = get_nano_time(&t1, &t2);
		//search_time += _time;
		/*if (res != check_list[i]) {
			if (res > check_list[i] && !check_correct(rules[res], packets[i])) {
				fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but return %d.", i, check_list[i], res);
				return -1;
			}
		}*/
		//int true_result = simple_search(rules, packets[i]);
		//if (res != true_result) {
		//	fprintf(stderr, "packet %d search result is uncorrect! true is %d, but result %d.\n", i, true_result, res);
		//	//return -1;
		//}
		//fprintf(res_fp, "Packet %d \t Result %d \t Time(um) %f\n", i, res, _time / 1000.0);
	}
	//clock_gettime(CLOCK_REALTIME, &t2);
	uint64_t _end = GetCPUCycle();
	search_time = _end - _start;
	//search_time = get_nano_time(&t1, &t2);
	//fclose(res_fp);
	//cout << "|- Average search time: " << search_time / packets.size() / 1000.0 << "um\n\n";
	cout << "|- Average search cycle: " << search_time / packets.size() << "\n\n";

	//ht.search_with_log(packets);



	// update
	int update_num = 5000;
	cout << "\nStart update...\n";
	random_device seed;
	mt19937 rd(seed());
	uniform_int_distribution<> dis(0, rules.size() * 0.7);
	double update_time = 0;

	for (int i = 0; i < update_num; ++i) {
		int cur_idx = dis(rd);
		//clock_gettime(CLOCK_REALTIME, &t1);
		uint64_t _start = GetCPUCycle();
		dbt.remove(rules[cur_idx]);
		dbt.insert(rules[cur_idx]);
		uint64_t _end = GetCPUCycle();
		//clock_gettime(CLOCK_REALTIME, &t2);
		//update_time += get_nano_time(&t1, &t2);
		update_time += (_end - _start);
	}
	//cout << "|- Average update time: " << update_time / (update_num * 2) / 1000.0 << "um\n\n";
	cout << "|- Average update cycle: " << update_time / (update_num * 2) << "\n\n";
}

void multi_thread_cycle(bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list, int thread_num)
{
	cout << "\nbuild for multi-thread...\n";

	DBTable dbt(rules, 4);
	dbt.construct();

	//random_device seed;
	//mt19937 rd(seed());
	//uniform_int_distribution<> dis(0, rules.size() * 0.7);
	srand(20);
	int rule_range = rules.size() * 0.5;
	int up_num[4] = { 5, 50, 500, 5000 };
	vector<int> up_idx[4];
	chrono::milliseconds up_step[4];
	up_step[0] = chrono::milliseconds(1000);
	up_step[1] = chrono::milliseconds(100);
	up_step[2] = chrono::milliseconds(10);
	up_step[3] = chrono::milliseconds(1);
	for (int i = 0; i < 4; ++i) {
		for (int k = 0; k < up_num[i]; ++k)up_idx[i].emplace_back(rand() % rule_range);
	}

	double throughput[32];
	atomic_bool start_test(false);
	thread threads[32];

	//int thread_num = 1;
	//for (; thread_num <= 32; thread_num *= 2) {
	start_test = false;
	// multi-thread read with write
	thread update_thread([&]()-> bool {
		struct timespec t1, t2;
		double s_time = 0;

		while (!start_test);

		for (int i = 0; i < 4; ++i) {
			for (int k = 0; k < up_num[i]; ++k) {
				uint64_t _start = GetCPUCycle();
				dbt.remove_multi_thread(rules[up_idx[i][k]]);
				dbt.insert_multi_thread(rules[up_idx[i][k]]);
				uint64_t _end = GetCPUCycle();
				s_time += (_end - _start);
				this_thread::sleep_for(up_step[i]);
			}
		}

		printf("\nupdate num --- stage1: %d stage2: %d stage3: %d stage4: %d\n", up_num[0], up_num[1], up_num[2], up_num[3]);
		int total_upNum = (up_num[0] + up_num[1] + up_num[2] + up_num[3]) * 2;
		printf("total operate num: %d avg update cycle: %f\n", total_upNum, s_time / total_upNum);

		this_thread::sleep_for(chrono::seconds(5));
		start_test = false;

		return true;
		});


	for (int i = 0; i < thread_num; ++i) {
		threads[i] = thread([&](int id)->bool
			{
				struct timespec t1, t2;
				double s_time = 0;
				uint64_t p_num = 0;
				int res;
				while (!start_test);

				while (start_test) {
					//printf("%d\n", j);
					uint64_t _start = GetCPUCycle();
					for (int p_id = 0; p_id < packets.size(); ++p_id) {
						//clock_gettime(CLOCK_REALTIME, &t1);
						res = dbt.search(packets[p_id]);
						//clock_gettime(CLOCK_REALTIME, &t2);
						//double _time = get_nano_time(&t1, &t2);
						//printf("%f\n", _time);
						//s_time += _time;
						//if (res != -1 && res != check_list[p_id]) {
						//	if (!check_correct(rules[res], packets[p_id])) {
						//		fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but return %d.", p_id, check_list[p_id], res);
						//		//printf("Packet %d search result is uncorrect! True is %d, but return %d.", j, check_list[j], res);
						//		//return false;
						//	}
						//}
					}
					uint64_t _end = GetCPUCycle();
					s_time += (_end - _start);
					p_num += packets.size();
				}


				throughput[id] =  s_time / p_num;
				//printf("%d %d %f\n", start_p, end_p, s_time / (end_p - start_p) / 1000.0);
				//printf("id: %d throughput: %f\n", id, s_time / (end_p - start_p) / 1000.0);
				return true;
			}, i);
	}

	start_test = true;
	double total_throughput = 0;
	update_thread.join();
	for (int i = 0; i < thread_num; ++i) {
		threads[i].join();
		total_throughput += throughput[i];
	}

	printf("\n%d thread with update avg search cycle %f\n", thread_num, total_throughput / thread_num);


	// multi-thread read
	start_test = false;
	for (int i = 0; i < thread_num; ++i) {
		threads[i] = thread([&](int id)->bool
			{
				struct timespec t1, t2;
				double s_time = 0;
				uint32_t p_num = 0;
				int res;
				while (!start_test);

				while (start_test) {
					//printf("%d\n", j);
					uint64_t _start = GetCPUCycle();
					for (int p_id = 0; p_id < packets.size(); ++p_id) {
						//clock_gettime(CLOCK_REALTIME, &t1);
						res = dbt.search(packets[p_id]);
						//clock_gettime(CLOCK_REALTIME, &t2);
						//double _time = get_nano_time(&t1, &t2);
						//printf("%f\n", _time);
						//s_time += _time;
						//if (res != -1 && res != check_list[p_id]) {
						//	if (!check_correct(rules[res], packets[p_id])) {
						//		fprintf(stderr, "Packet %d search result is uncorrect! True is %d, but return %d.", p_id, check_list[p_id], res);
						//		//printf("Packet %d search result is uncorrect! True is %d, but return %d.", j, check_list[j], res);
						//		//return false;
						//	}
						//}
					}
					uint64_t _end = GetCPUCycle();
					s_time += (_end - _start);
					p_num += packets.size();
				}


				throughput[id] = s_time / p_num;
				//printf("%d %d %f\n", start_p, end_p, s_time / (end_p - start_p) / 1000.0);
				//printf("id: %d throughput: %f\n", id, s_time / (end_p - start_p) / 1000.0);
				return true;
			}, i);
	}

	start_test = true;
	sleep(35);
	start_test = false;
	total_throughput = 0;
	for (int i = 0; i < thread_num; ++i) {
		threads[i].join();
		total_throughput += throughput[i];
	}
	printf("\n%d thread avg search cycle %f\n", thread_num, total_throughput / thread_num);

	//}
}

void cacu_skew(vector<Rule>& rules)
{
	SkewNode root;
	for (auto& r : rules) {
		if (r.sip_length != 0)root.rules.emplace_back(&r);
	}
	root.level = 1;
	vector<double> skews;
	vector<int> nums;
	list<SkewNode*> Nlist;
	Nlist.emplace_back(&root);
	skews.resize(32);
	nums.resize(32);
	for (int i = 0; i < 32; ++i) { skews[i] = 0; nums[i] = 0; }
	while (!Nlist.empty())
	{
		SkewNode* node = Nlist.front(); Nlist.pop_front();
		vector<Rule*> zero, one;
		double light, heavy;
		for (auto& r : node->rules) {
			if (r->sip_length < node->level)continue;
			if ((r->ip.i_32.sip & getBit[node->level - 1]) == 0)zero.emplace_back(r);
			else one.emplace_back(r);
		}
		if (zero.size() > one.size()) {
			heavy = zero.size();
			light = one.size();
		}
		else {
			heavy = one.size();
			light = zero.size();
		}
		if (light != 0 && heavy != 0) { 
			skews[node->level - 1] += (1 - light / heavy); 
			nums[node->level - 1] += 1;
		}
		if (!zero.empty()) {
			SkewNode* newnode = new SkewNode();
			newnode->rules.swap(zero);
			newnode->level = node->level + 1;
			node->lchild = newnode;
			if (newnode->level != 33)Nlist.emplace_back(newnode);
		}
		if (!one.empty()) {
			SkewNode* newnode = new SkewNode();
			newnode->rules.swap(one);
			newnode->level = node->level + 1;
			node->rchild = newnode;
			if (newnode->level != 33)Nlist.emplace_back(newnode);
		}
		node->rules.swap(zero);
	}
	double skew = 0;
	int level = 0;
	for (int i = 0; i < 32; ++i) {
		if (nums[i] != 0) { skew += (skews[i] / nums[i]); ++level; }
	}
	printf("\n%f\n", skew / level);

	for (auto& r : rules) {
		if (r.dip_length != 0)root.rules.emplace_back(&r);
	}
	root.lchild = NULL; root.rchild = NULL;
	Nlist.emplace_back(&root);
	for (int i = 0; i < 32; ++i) { skews[i] = 0; nums[i] = 0; }
	while (!Nlist.empty())
	{
		SkewNode* node = Nlist.front(); Nlist.pop_front();
		vector<Rule*> zero, one;
		double light, heavy;
		for (auto& r : node->rules) {
			if (r->dip_length < node->level)continue;
			if ((r->ip.i_32.dip & getBit[node->level - 1]) == 0)zero.emplace_back(r);
			else one.emplace_back(r);
		}
		if (zero.size() > one.size()) {
			heavy = zero.size();
			light = one.size();
		}
		else {
			heavy = one.size();
			light = zero.size();
		}
		if (light != 0 && heavy != 0) {
			skews[node->level - 1] += (1 - light / heavy);
			nums[node->level - 1] += 1;
		}
		if (!zero.empty()) {
			SkewNode* newnode = new SkewNode();
			newnode->rules.swap(zero);
			newnode->level = node->level + 1;
			node->lchild = newnode;
			if (newnode->level != 33)Nlist.emplace_back(newnode);
		}
		if (!one.empty()) {
			SkewNode* newnode = new SkewNode();
			newnode->rules.swap(one);
			newnode->level = node->level + 1;
			node->rchild = newnode;
			if (newnode->level != 33)Nlist.emplace_back(newnode);
		}
		node->rules.swap(zero);
	}
	skew = 0; level = 0;
	for (int i = 0; i < 32; ++i) {
		if (nums[i] != 0) { skew += (skews[i] / nums[i]); ++level; }
	}

	printf("\n%f\n", skew / level);
}
