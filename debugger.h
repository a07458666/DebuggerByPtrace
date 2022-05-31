#ifndef __DEBUGGER_H__
#define __DEBUGGER_H__

#include <string>
#include <map>
#include <vector>
#include <elf.h>

#define BASE 16
#define MAX_BUF_SIZE 256
#define ERR -1
#define ElfN_Ehdr Elf64_Ehdr
#define GETPOSE printf("** file %s, line %d\n", __FILE__, __LINE__);
typedef unsigned long reg_t;
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
        int m_wait_status;
        reg_t m_start_point;
        std::map<reg_t, reg_t> break_points;
        ElfN_Ehdr m_f_header;

        int getReg(struct user_regs_struct *regs);
        int getRegs();
        int showRegs(struct user_regs_struct regs);
        int getOneReg(char* target);
        int setReg(char* target, char* val);
        int dumpCode(long code, char* msg);
        int doCommand(std::vector<std::string> *cmds);
        int loadProgram(char* program);

        int cont();
        int step();
        int setBreakPoint(reg_t break_point);
        int show_vmmap();
        int load_maps(pid_t pid, std::map<range_t, map_entry_t>& loaded);
        reg_t convertStrToNumber(char* val);
        int checkProgramState();
        int bufferToCmds(char *buf, std::vector<std::string> *cmds);
        int readELF(char* program);
        States setStates(States newStates);
        States getStates();
    public:
        Debugger(char * script, char* program);
        ~Debugger();
        
        int runByStdin();
        int runByScript();
};


#endif //__DEBUGGER_H__