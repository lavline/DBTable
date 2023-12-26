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


#include <stdlib.h>
#include <random>
#include <unistd.h>
#include <getopt.h>
#include "read.h"
#include "method.h"

using namespace std;

int main(int argc, char* argv[]) {
	// process argument
	if (argc == 1) { fprintf(stderr, "use -h(--help) to print the usage guideline.\n"); return 0; }
	//string ipFieldName[8] = { "Sip1", "Sip2", "Sip3", "Sip4", "Dip1", "Dip2", "Dip3", "Dip4" };
	vector<Rule> rules;
	vector<Packet> packets;
	vector<int> check_list;
	struct timespec t1, t2;

	bool enable_log = false;
	bool enable_search_config = true;
	bool enable_update = false;
	int log_level = 1; // {1,2,3}
	int thread_num = 1;
	bool enable_multi_thread = false;

	int opt;
	struct option opts[] = {
		{"ruleset", 1, NULL, 'r'},
		{"packet", 1, NULL, 'p'},
		{"log", 1, NULL, 'l'},
		{"update", 0, NULL, 'u'},
		{"binth", 1, NULL, 'b'},
		{"th_b", 1, NULL, 'e'},
		{"th_c", 1, NULL, 'c'},
		{"top-k", 1, NULL, 'k'},
		{"thread", 1, NULL, 't'},
		{"shift", 0, NULL, 's'},
		{"help", 0, NULL, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "r:p:l:b:e:c:k:t:ush", opts, NULL)) != -1) {
		switch (opt)
		{
		case 'r':
			cout << "Read ruleset:  " << optarg << endl;
			if (!read_rules(optarg, rules)) return -1;
			break;
		case 'p':
			cout << "Rread packets: " << optarg << endl;
			if (!read_packets(optarg, packets, check_list)) return -1;
			break;
		case 'l':
			enable_log = true;
			log_level = atoi(optarg);
			if (log_level < 1 || log_level>3) {
				fprintf(stderr, "error-unknown log level %d.\n", log_level);
				return -1;
			}
			cout << "Enable log:    level " << log_level << endl;
			break;
		case 't':
			thread_num = atoi(optarg);
			break;
		case 'b':
			BINTH = atoi(optarg);
			break;
		case 'e':
			END_BOUND = atof(optarg);
			break;
		case 'c':
			C_BOUND = atoi(optarg);
			break;
		case 'k':
			TOP_K = atoi(optarg);
			break;
		case 'u':
			enable_update = true;
			cout << "Enable update\n";
			break;
		case 's':
			cout << "shif test\n";
			break;
		case 'h':
			cout << "\n************************************************************************************************************************************************************\n";
			cout << "* -r(--ruleset): Input the rule set file. This argument must be specified. (Example: [-r acl1])                                                            *\n";
			cout << "* -p(--packet):  Input the packet set file. If not set, the program will generate randomly. (Example: [-p acl1_trace])                                     *\n";
			cout << "* -l(--log):     Enable the log. Have three level 1-3. (Example: [-l 3])                                                                                   *\n";
			cout << "* -u(--update):  Enable update. (Example: [-u])                                                                                                            *\n";
			cout << "* -h(--help):    Print the usage guideline.                                                                                                                *\n";
			cout << "************************************************************************************************************************************************************\n\n";
			if (argc == 2)return 0;
			break;
		case '?':
			fprintf(stderr, "error-unknown argument -%c.", optopt);
			return -1;
		default:
			break;
		}
	}

	single_thread(enable_update, rules, packets, check_list);
	//shif_rulesets();
	//cacu_skew(rules);

	//ana_ruleset(rules);

	cout << "\nprogram complete\n\n";
	return 0;
}

