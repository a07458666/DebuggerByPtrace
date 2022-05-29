#ifndef __DEBUGGER_H__
#define __DEBUGGER_H__

#include <string>
#include <map>

typedef struct range_s {
	unsigned long begin, end;
}	range_t;

typedef struct map_entry_s {
	range_t range;
	int perm;
	long offset;
    std::string permStr;
	std::string name;
}	map_entry_t;

bool operator<(range_t r1, range_t r2);

enum States {NotLoadedStates, LoadedStates, RunningStates};
// enum Cmd {break, cont, delete, disasm, dump, exit, get, getregs, help, list, load, run, vmmap, set, si, start};

class Debugger{
    private:
        States m_states;
        pid_t m_child_pid;
        char *m_program;
        char *m_script;
    public:
        Debugger(char * script, char* program);
        ~Debugger();
        int trace();
        int getRegs();
        int showRegs(struct user_regs_struct regs);
        int getOneReg(char* target);
        void dumpCode(long addr, long code);
        int getCommand();
        int loadProgram(char* program);
        int run();
        int cont();
        int step();
        int setBreakPoint();
        int show_vmmap();
        int load_maps(pid_t pid, std::map<range_t, map_entry_t>& loaded);
};


#endif //__DEBUGGER_H__