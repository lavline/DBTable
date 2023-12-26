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

#ifndef _METHODS_H
#define _MRTHODS_H
#include <thread>
#include <random>
#include <chrono>
#include <atomic>
#include <unistd.h>
#include <time.h>
#include <list>
#include "core.h"
#include "read.h"
#include "gen.h"

using namespace std;

void single_thread(bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list);
void multi_thread(bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list, int thread_num);
void shif_rulesets();

void single_thread_cycle(bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list);
void multi_thread_cycle(bool enable_update, vector<Rule>& rules, vector<Packet>& packets, vector<int>& check_list, int thread_num);
void cacu_skew(vector<Rule>& rules);

#endif // _METHODS_H