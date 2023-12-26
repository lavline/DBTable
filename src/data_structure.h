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

#ifndef __DATA_STRUCTURE_H_
#define __DATA_STRUCTURE_H_
#include <stdio.h>
#include <vector>
#include <cstring>
#include <math.h>
#include <algorithm>
#include <stdint.h>
#include <time.h>
#include <atomic>
#include <thread>

//using namespace std;
#define TRASH_CAPACITY 5555

extern uint32_t maskBit[33];

template<typename T>
struct Trash
{
	T** data;
	int size;
	std::vector<T*> list;

	Trash();
	~Trash();
	void push(T* t);
};

template<typename T>
struct myVector
{
private:
	T* data;
	uint64_t data_size;
	uint64_t vec_capacity;
public:
	myVector();
	myVector(struct myVector& val);
	~myVector();

	uint64_t size();
	uint64_t capacity();
	bool empty();
	void free();
	void swap(struct myVector<T>& val);
	void swap(T* p, uint64_t _size, uint64_t _capa);
	T* front();
	T& operator[](uint64_t i);
	void operator=(struct myVector<T>& val);
	void emplace_back(T& val);
	void insert(T& val, uint64_t i);
	void remove(uint64_t i);
	void insert_recycle(T& val, uint64_t i);
	void remove_recycle(uint64_t i);
};

union MASK {
	struct {
		uint32_t smask;
		uint32_t dmask;
	}i_32;
	uint64_t i_64;
};

union IP
{
	uint64_t i_64;
	struct {
		uint32_t sip;
		uint32_t dip;
	}i_32;
	struct {
		uint8_t sip[4];
		uint8_t dip[4];
	}i_8;
};
struct PROTOCOL
{
	uint8_t val;
	uint8_t mask;
};

struct Rule {
	uint32_t pri;  //priority
	PROTOCOL protocol;
	uint8_t sip_length;
	uint8_t dip_length;
	uint16_t Port[2][2];
	IP ip;
	MASK mask;
};

struct CacuRule
{
	uint32_t pri;  //priority
	short fetch_bit;
	uint8_t sip_length;
	uint8_t dip_length;
	uint16_t Port[2][2];
	IP ip;
	bool is_first;
	uint32_t size;

	CacuRule() : is_first(false) {}
};

struct Packet
{
	uint32_t protocol;
	IP ip;
	uint16_t Port[2];
};

struct BitRank
{
	int id;
	double rank;
	int count;
};

struct Bucket
{
	uint32_t pri;
	//std::vector<Rule> rules;
	myVector<Rule> rules;
	Bucket() : pri(0xFFFFFFFF) {}
};

struct port_node
{
	uint32_t pri;
	uint16_t type;
	uint16_t mask;
	Bucket* buckets;
	port_node() :  pri(0xFFFFFFFF), mask(0), buckets(NULL) {}
};

struct prefix_tuple
{
	uint32_t pri;
	IP prefix;
	port_node* pNodes[2];
	//std::vector<Rule> rules;
	myVector<Rule> rules;
	struct prefix_tuple* next;
	prefix_tuple() : pri(0xFFFFFFFF), next(NULL) { pNodes[0] = pNodes[1] = NULL; }
};

struct Tuple
{
	uint32_t pri;
	MASK key;
	uint32_t mask;
	uint32_t ptuple_num;
	prefix_tuple* ptuples;
	Tuple(MASK _key) : pri(0xFFFFFFFF), mask(7), ptuple_num(0), key(_key) { }
};

struct ip_node
{
	uint32_t pri;
	//std::vector<Rule> rules;
	myVector<Rule> rules;
	std::vector<Tuple> tuples;
	char*** prefix_down;
	ip_node() : pri(0xFFFFFFFF), prefix_down(NULL) {}
};

struct SubSet
{
	uint32_t size;
	uint32_t nodes_num;
	MASK mask;
	ip_node* ipNodes;
	SubSet() : size(0), nodes_num(0), ipNodes(NULL) { mask.i_64 = 0; }
};

extern Trash<Rule> rule_trash;

template<typename T>
Trash<T>::Trash() : size(0)
{
	data = new T* [TRASH_CAPACITY]();
}

template<typename T>
Trash<T>::~Trash()
{
	for (int i = 0; i < size; ++i)delete[] data[i];
	delete[] data;
	for (auto& d : list)delete[] d;
}

template<typename T>
void Trash<T>::push(T* t)
{
	if (size < TRASH_CAPACITY) {
		data[size] = t;
		++size;
	}
	else {
		/*T** tmp;
		tmp = new T* [TRASH_CAPACITY]();
		memcpy(tmp, data, TRASH_CAPACITY * sizeof(T*));
		std::thread free_trash([&]()->void {
			for (int i = 0; i < TRASH_CAPACITY; ++i) {
				delete[] tmp[i];
			}
			delete[] tmp;
			});*/
		for (int i = 0; i < TRASH_CAPACITY; ++i) {
			delete[] data[i];
		}
		data[0] = t;
		size = 1;
		//free_trash.detach();
	}
}


template<typename T>
myVector<T>::myVector() : vec_capacity(8), data_size(0)
{
	data = new T[8]();
}

template<typename T>
myVector<T>::myVector(myVector& val) : vec_capacity(val.capacity()), data_size(val.size())
{
	data = new T[vec_capacity]();
	memcpy(data, val.front(), data_size * sizeof(T));
}

template<typename T>
myVector<T>::~myVector()
{
	delete[] data;
}

template<typename T>
uint64_t myVector<T>::size()
{
	return data_size;
}

template<typename T>
uint64_t myVector<T>::capacity()
{
	return vec_capacity;
}

template<typename T>
bool myVector<T>::empty()
{
	if (data_size == 0)return true;
	else return false;
}

template<typename T>
void myVector<T>::free()
{
	data_size = 0;
	vec_capacity = 8;
	delete[] data;
	data = new T[8]();
}

template<typename T>
void myVector<T>::swap(struct myVector<T>& val)
{
	T* tmp_data = val.front();
	uint64_t tmp_size = val.size();
	uint64_t tmp_capa = val.capacity();
	val.swap(data, data_size, vec_capacity);
	data = tmp_data;
	data_size = tmp_size;
	vec_capacity = tmp_capa;
}

template<typename T>
void myVector<T>::swap(T* p, uint64_t _size, uint64_t _capa)
{
	data = p;
	data_size = _size;
	vec_capacity = _capa;
}

template<typename T>
T* myVector<T>::front()
{
	return data;
}

template<typename T>
T& myVector<T>::operator[](uint64_t i)
{
	return data[i];
}

template<typename T>
void myVector<T>::operator=(myVector<T>& val)
{
	if (this != &val) {
		delete[] data;
		data = new T[val.capacity()]();
		memcpy(data, val.front(), val.size() * sizeof(T));
		data_size = val.size();
		vec_capacity = val.capacity();
	}
}

template<typename T>
void myVector<T>::emplace_back(T& val)
{
	if (data_size + 1 < vec_capacity) {
		data[data_size] = val;
		++data_size;
	}
	else {
		vec_capacity <<= 1;
		T* tmp = data;
		T* p = new T[vec_capacity]();
		memcpy(p, data, data_size * sizeof(T));
		p[data_size] = val;
		data = p;
		++data_size;
		delete[] tmp;
	}
}

template<typename T>
void myVector<T>::insert_recycle(T& val, uint64_t i)
{
	if (data_size + 1 < vec_capacity)vec_capacity <<= 1;
	T* tmp = new T[vec_capacity]();
	memcpy(tmp, data, i * sizeof(T));
	memcpy(tmp + i + 1, data + i, (data_size - i) * sizeof(T));
	tmp[i] = val;
	rule_trash.push(data);
	//rule_trash.list.emplace_back(data);
	data = tmp;
	++data_size;
}

template<typename T>
void myVector<T>::remove_recycle(uint64_t i)
{
	T* tmp = new T[vec_capacity]();
	memcpy(tmp, data, i * sizeof(T));
	memcpy(tmp + i, data + i + 1, (data_size - i - 1) * sizeof(T));
	rule_trash.push(data);
	//rule_trash.list.emplace_back(data);
	--data_size;
	data = tmp;
}

template<typename T>
void myVector<T>::insert(T& val, uint64_t i)
{
	if (data_size + 1 < vec_capacity) {
		memmove(data + i + 1, data + i, (data_size - i) * sizeof(T));
		data[i] = val;
		++data_size;
	}
	else {
		vec_capacity <<= 1;
		T* tmp = data;
		T* p = new T[vec_capacity]();
		memcpy(p, data, i * sizeof(T));
		memcpy(p + i + 1, data + i, (data_size - i) * sizeof(T));
		p[i] = val;
		data = p;
		++data_size;
		delete[] tmp;
	}
}

template<typename T>
void myVector<T>::remove(uint64_t i)
{
	memmove(data + i, data + i + 1, (data_size - i - 1) * sizeof(T));
	--data_size;
}


typedef struct SkewNode
{
	std::vector<Rule*> rules;
	SkewNode* lchild;
	SkewNode* rchild;
	int level;
	SkewNode() :lchild(NULL), rchild(NULL) {}
}SkewNode;

#endif //__DATA_STRUCTURE_H_