#ifndef __DEBUGGER_H__
#define __DEBUGGER_H__

#include <string>
#include <map>
#include <vector>
#include <elf.h>
#include <capstone/capstone.h>

using namespace std;

#define	PEEKSIZE	8
#define DUMP_SIZE 16
#define BASE 16
#define MAX_BUF_SIZE 1024
#define ERR -1
#define MAX_DUMP_INSTRUCTIONS 10
#define ELF_32_BIT_TYPE 1
#define ELF_64_BIT_TYPE 2
#define GETPOSE printf("** file %s, line %d\n", __FILE__, __LINE__);
#define BYTE_MASK 0x00000000000000ff 
#define BREAK_INSTRUCTION 0xcc

// Msg
#define HELP_MGS "- break {instruction-address}: add a break point\n- cont: continue execution\n- delete {break-point-id}: remove a break point\n- disasm addr: disassemble instructions in a file or a memory region\n- dump addr: dump memory content\n- exit: terminate the debugger\n- get reg: get a single value from a register\n- getregs: show registers\n- help: show this message\n- list: list break points\n- load {path/to/a/program}: load a program\n- run: run the program\n- vmmap: show memory layout\n- set reg val: get a single value to a register\n- si: step into instruction\n- start: start the program and stop at the first instruction\n"
#define MSG_MUST_NOT_LOADED_STATES "**states must be NotLoadedStates\n"
#define MSG_MUST_LOADED_STATES "** states must be LoadedStates\n"
#define MSG_MUST_RUNNING_OR_LOADED "** states must be RunningStates or LoadedStates\n"
#define MSG_MUST_RUNNING "** states must be RunningStates\n"
#define MSG_NO_REG_NAME "** no regName is given\n"
#define MSG_NO_REG_NAME_OR_VAL "** no regName or regVal\n"
#define MSG_NO_ADDR "** no address is given\n"
#define MSG_OUT_OF_RANGE  "** the address is out of the range of the text segment\n"
#define MSG_ALREADY_EXISTS "** the breakpoint is already exists.\n"
typedef unsigned long long reg_t;

typedef struct range_s {
	reg_t begin, end;
}	range_t;

typedef struct map_entry_s {
	range_t range;
	int perm;
	long offset;
    std::string permStr;
	std::string name;
}	map_entry_t;

typedef struct elf_info_s {
    reg_t entry_addr;
    reg_t text_size;
    reg_t text_min_addr;
    reg_t text_max_addr;
} elf_info_t;

class instruction {
public:
	unsigned char bytes[16];
	int size;
	string opr, opnd;
};

bool operator<(range_t r1, range_t r2);

enum States {NotLoadedStates, LoadedStates, RunningStates};
// enum Cmd {break, cont, delete, disasm, dump, exit, get, getregs, help, list, load, run, vmmap, set, si, start};

class Debugger{
    private:
        // disasm
        csh cshandle = 0;
        map<long long, instruction> instructions;
        int init_disasm();
        int close_disasm();
        void print_instruction(long long addr, instruction *in);
        unsigned long disassemble(pid_t proc, unsigned long long rip);

        // elf
        int elf_type = 0;
        Elf32_Ehdr m_elf_header32;
        Elf32_Shdr m_sh_table32;
        Elf64_Ehdr m_elf_header64;
        Elf64_Shdr m_sh_table64;
        elf_info_t m_elf_info;

        States m_states;
        pid_t m_child_pid;
        string m_program;
        string m_script;
        int m_wait_status;
        std::vector<reg_t> m_breakpoint_addrs;
        std::map<reg_t, reg_t> m_breakpoints;
        
        int getReg(struct user_regs_struct *regs);
        int getRegs();
        int showRegs(struct user_regs_struct regs);
        int getOneReg(char* target);
        int setReg(char* target, char* val);
        int dumpCode(long code, char* msg);
        int dumpCodeASCII(reg_t addr);
        int doCommand(std::vector<std::string> *cmds);
        int loadProgram(string program);
        int list();
        int deleteBreak(int idx);
        int cont();
        int step();
        int setBreakPoint(reg_t break_point);
        int p_setBreakpoint(reg_t break_point);
        bool checkBreakpoint(reg_t break_point);
        int show_vmmap();
        int load_maps(pid_t pid, std::map<range_t, map_entry_t>& loaded);
        reg_t convertStr2ul(char* val);
        int checkProgramState(reg_t before_rip);
        int bufferToCmds(char *buf, std::vector<std::string> *cmds);
        int readELF(string program);
        States setStates(States newStates);
        States getStates();
        int recoverBeackpoint(struct user_regs_struct regs);
        int setAllBreakpoin();
        int disasm(int instructionsCount, reg_t addr);
        int dump(reg_t addr);
        reg_t peek_code(reg_t addr);
        int peek_byte_code(reg_t addr, reg_t code);
        reg_t peek_breakpoint_code(reg_t addr);
        bool checkAddrInTextRange(reg_t addr);
    public:
        Debugger(char * script, char* program);
        ~Debugger();
        
        int runByStdin();
        int runByScript();
};


#endif //__DEBUGGER_H__