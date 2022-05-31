#ifndef __DUMP_CODE_H__
#define __DUMP_CODE_H__

#include <string>
#include <map>
#include <capstone/capstone.h>

using namespace std;

#define	PEEKSIZE	8

class instruction1 {
public:
	unsigned char bytes[16];
	int size;
	string opr, opnd;
};

static csh cshandle = 0;
static map<long long, instruction1> instructions;
int init();
int closeHandle();
void print_instruction(long long addr, instruction1 *in);
unsigned long disassemble(pid_t proc, unsigned long long rip);

#endif //__DUMP_CODE_H__