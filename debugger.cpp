#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <iostream>
#include <cstring>

// elf
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "debugger.h"

using namespace std;

#define HELP_MGS "- break {instruction-address}: add a break point\n- cont: continue execution\n- delete {break-point-id}: remove a break point\n- disasm addr: disassemble instructions in a file or a memory region\n- dump addr: dump memory content\n- exit: terminate the debugger\n- get reg: get a single value from a register\n- getregs: show registers\n- help: show this message\n- list: list break points\n- load {path/to/a/program}: load a program\n- run: run the program\n- vmmap: show memory layout\n- set reg val: get a single value to a register\n- si: step into instruction\n- start: start the program and stop at the first instruction\n"

bool operator<(range_t r1, range_t r2) {
	if(r1.begin < r2.begin && r1.end < r2.end) return true;
	return false;
}

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

void str2lowerStr(char * scrip)
{
    int length = sizeof(scrip)/sizeof(char);
    for (int i = 0; i < length; ++i)
    {
        scrip[i] = tolower(scrip[i]);
    }
    return;
}

Debugger::Debugger(char * script, char* program)
{
    m_states = NotLoadedStates;
    m_program.assign(program);
    m_script.assign(script);
    if (strcmp(program, "") != 0) 
    {
        if (readELF(program) != 0) errquit("** readELF");
    }
}

Debugger::~Debugger(){
    close_disasm();
}

int Debugger::doCommand(std::vector<std::string> *cmds)
{
    int ret = 0;
    if (cmds->size() == 0) return 0;
    char* cmd = (char *)cmds->at(0).c_str();
    str2lowerStr(cmd);
    if (strcmp("load", cmd) == 0)
    {   
        if(getStates() == NotLoadedStates)
        {
            if (cmds->size() < 2) 
            {
                printf("** no file is given\n");
                return 0;
            }
            m_program = (char*)cmds->at(1).c_str();
            if (readELF(m_program) != 0) errquit("** readELF");
        }
        else
        {
            printf(MSG_MUST_NOT_LOADED_STATES);
        }
    }
    else if (strcmp("start", cmd) == 0)
    {
        if (getStates() == LoadedStates)
        {
            // printf("** pid %d\n", m_child_pid);
            if (loadProgram(m_program) != 0) errquit("**loadProgram");
        }
        else
        {
            printf(MSG_MUST_LOADED_STATES);
        }
    }
    else if (strcmp("run", cmd) == 0 || strcmp("r", cmd) == 0)
    {
        if (getStates() == RunningStates)
        {
            printf("** program %s is already running\n", m_program.c_str());
            cont();
        }
        else if (getStates() == LoadedStates)
        {
            printf("** run program '%s'\n", m_program.c_str());
            if (loadProgram(m_program) != 0) errquit("**loadProgram");
            cont();
        }
        else
        {
            printf(MSG_MUST_RUNNING_OR_LOADED);
        }
    }
    else if (strcmp("cont", cmd) == 0 || strcmp("c", cmd) == 0)
    {
        if (getStates() == RunningStates)
        {
            cont();
        }
        else
        {
            printf(MSG_MUST_RUNNING);
        }
    }
    else if (strcmp("get", cmd) == 0 || strcmp("g", cmd) == 0)
    {
        if (getStates() == RunningStates)
        {
            if (cmds->size() < 2) 
            {
                printf(MSG_NO_REG_NAME);
                return 0;
            }
            char* regName = (char *)cmds->at(1).c_str();
            getOneReg(regName);
        }
        else
        {
            printf(MSG_MUST_RUNNING);
        }
    }
    else if (strcmp("set", cmd) == 0 || strcmp("s", cmd) == 0)
    {
        if (getStates() == RunningStates)
        {   
            if (cmds->size() < 3) 
            {
                printf(MSG_NO_REG_NAME_OR_VAL);
                return 0;
            }
            char* regName = (char *)cmds->at(1).c_str();
            char* regVal = (char *)cmds->at(2).c_str();
            setReg(regName,  regVal);
        }
        else
        {
            printf(MSG_MUST_RUNNING);
        }
    }
    else if (strcmp("getregs", cmd) == 0)
    {
        if (getStates() == RunningStates)
        {
            getRegs();
        }
        else
        {
            printf(MSG_MUST_RUNNING);
        }
    }
    else if (strcmp("si", cmd) == 0)
    {
        if (getStates() == RunningStates)
        {
            step();
        }
        else
        {
            printf(MSG_MUST_RUNNING);
        }
    }
    else if (strcmp("list", cmd) == 0 || strcmp("l", cmd) == 0)
    {
        list();
    }
    else if (strcmp("delete", cmd) == 0)
    {
        if (getStates() == RunningStates)
        {
            if (cmds->size() < 2) 
            {
                printf(MSG_NO_ADDR);
                return 0;
            }
            char* idx_str = (char *)cmds->at(1).c_str();
            unsigned long idx = convertStr2ul(idx_str);
            deleteBreak((int)idx);
        }
        else
        {
            printf(MSG_MUST_RUNNING);
        }
    }
    else if (strcmp("dump", cmd) == 0)
    {
        if (getStates() == RunningStates)
        {
            if (cmds->size() < 2) 
            {
                printf(MSG_NO_ADDR);
                return 0;
            }
            char* addr = (char *)cmds->at(1).c_str();
            reg_t addr_val = convertStr2ul(addr);
            dump(addr_val);
        }
        else
        {
            printf(MSG_MUST_RUNNING);
        }
    }
    else if (strcmp("vmmap", cmd) == 0 || strcmp("m", cmd) == 0)
    {
        if (getStates() == RunningStates)
        {
            if(show_vmmap() < 0) errquit("** show_vmmap");
        }
        else
        {
            printf(MSG_MUST_RUNNING);
        }
    }
    else if (strcmp("break", cmd) == 0 || strcmp("b", cmd) == 0)
    {
        if (getStates() == RunningStates)
        {
            if (cmds->size() < 2) 
            {
                printf(MSG_NO_ADDR);
                return 0;
            }
            char* break_point = (char *)cmds->at(1).c_str();
            reg_t break_val = convertStr2ul(break_point);
            setBreakPoint(break_val);
        }
        else
        {
            printf(MSG_MUST_RUNNING);
        }
    }
    else if (strcmp("disasm", cmd) == 0 || strcmp("d", cmd) == 0)
    {   
        if (getStates() == RunningStates)
        {
            if (cmds->size() < 2) 
            {
                printf(MSG_NO_ADDR);
                return 0;
            }
            char* addr = (char *)cmds->at(1).c_str();
            reg_t addr_val = convertStr2ul(addr);
            int ret = disasm(MAX_DUMP_INSTRUCTIONS, addr_val);
        }
        else
        {
            printf(MSG_MUST_RUNNING);
        }
        
    }
    else if (strcmp("exit", cmd) == 0 || strcmp("q", cmd) == 0)
    {
        printf("**exit\n");
        ret = -1;
    }
    else if(strcmp("help", cmd) == 0 || strcmp("h", cmd) == 0)
    {
        printf(HELP_MGS);
    }
    else
    {
        printf("**not define cmd %s\n", cmd);
    }
    fflush(stdout);
    return ret;
}

int Debugger::cont()
{
    struct user_regs_struct regs;
    getReg(&regs);
    recoverBeackpoint(regs);
    if(ptrace(PTRACE_CONT, m_child_pid,0 ,0) < 0) errquit("**ptrace@cont");
    if(waitpid(m_child_pid, &m_wait_status, 0) < 0) errquit("**waitpid");
    checkProgramState(regs.rip);
    return 0;
}

// cmd si
int Debugger::step()
{
    struct user_regs_struct regs;
    getReg(&regs);
    recoverBeackpoint(regs);
    if (ptrace(PTRACE_SINGLESTEP, m_child_pid, 0, 0) < 0) errquit("** ptrace@STEP");
    if (waitpid(m_child_pid, &m_wait_status, 0) < 0) errquit("** setp");
    checkProgramState(regs.rip);
    return 0;
}

// cmd list (list all beack point)
int Debugger::list()
{
    int count = 0;
    for (int i = 0; i < m_breakpoint_addrs.size(); ++i)
    {
        printf("  %d: %llx\n",i, m_breakpoint_addrs[i]);
    }
    return 0;
}

int Debugger::getRegs()
{
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, m_child_pid, 0, &regs) != 0)
        errquit("getRegs ptrace(PTRACE_GETREGS)");
    showRegs(regs);
    return 0;
}

int Debugger::showRegs(struct user_regs_struct regs)
{
    printf("RAX %-16llx\tRBX %-16llx\tRCX %-16llx\tRDX %-16llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
    printf("R8  %-16llx\tR9  %-16llx\tR10 %-16llx\tR11 %-16llx\n", regs.r8 , regs.r9 , regs.r10, regs.r11);
    printf("R12 %-16llx\tR13 %-16llx\tR14 %-16llx\tR15 %-16llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
    printf("RDI %-16llx\tRSI %-16llx\tRBP %-16llx\tRSP %-16llx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
    printf("RIP %-16llx\tFLAGS %016llx\n", regs.rip, regs.eflags);
    return 0;
}

int Debugger::getReg(struct user_regs_struct *regs)
{
    if(ptrace(PTRACE_GETREGS, m_child_pid, 0, regs) != 0)
        errquit("** getOneReg ptrace(PTRACE_GETREGS)");
    return 0;
}

int Debugger::getOneReg(char* target)
{   
    // printf("target %s\n", target);
    struct user_regs_struct regs;
    getReg(&regs);
    
    if (strcmp("rip", target) == 0) printf("rip = %lld (0x%llx)\n", regs.rip, regs.rip);
    else if (strcmp("flags", target) == 0) printf("flags = %lld (0x%llx)\n", regs.eflags, regs.eflags);
    
    else if (strcmp("rax", target) == 0) printf("rax = %lld (0x%llx)\n", regs.rax, regs.rax);
    else if (strcmp("rbx", target) == 0) printf("rbx = %lld (0x%llx)\n", regs.rbx, regs.rbx);
    else if (strcmp("rcx", target) == 0) printf("rcx = %lld (0x%llx)\n", regs.rcx, regs.rcx);
    else if (strcmp("rdx", target) == 0) printf("rdx = %lld (0x%llx)\n", regs.rdx, regs.rdx);

    else if (strcmp("r8", target) == 0) printf("r8 = %lld (0x%llx)\n", regs.r8, regs.r8);
    else if (strcmp("r9", target) == 0) printf("r9 = %lld (0x%llx)\n", regs.r9, regs.r9);
    else if (strcmp("r10", target) == 0) printf("r10 = %lld (0x%llx)\n", regs.r10, regs.r10);
    else if (strcmp("r11", target) == 0) printf("r11 = %lld (0x%llx)\n", regs.r11, regs.r11);

    else if (strcmp("r12", target) == 0) printf("r12 = %lld (0x%llx)\n", regs.r12, regs.r12);
    else if (strcmp("r13", target) == 0) printf("r13 = %lld (0x%llx)\n", regs.r13, regs.r13);
    else if (strcmp("r14", target) == 0) printf("r14 = %lld (0x%llx)\n", regs.r14, regs.r14);
    else if (strcmp("r15", target) == 0) printf("r15 = %lld (0x%llx)\n", regs.r15, regs.r15);

    else if (strcmp("rdi", target) == 0) printf("rdi = %lld (0x%llx)\n", regs.rdi, regs.rdi);
    else if (strcmp("rsi", target) == 0) printf("rsi = %lld (0x%llx)\n", regs.rsi, regs.rsi);
    else if (strcmp("rbp", target) == 0) printf("rbp = %lld (0x%llx)\n", regs.rbp, regs.rbp);
    else if (strcmp("rsp", target) == 0) printf("rsp = %lld (0x%llx)\n", regs.rsp, regs.rsp);
    else printf("** not find %s reg\n", target);
    return 0;
}

reg_t Debugger::convertStr2ul(char* val)
{
    reg_t ul;
    char *stopstring;                                                   
    ul = strtoul(val, &stopstring, BASE);
    // printf("   strtoul = %lld (base %d)\n", ul, BASE);                            
    // printf("   Stopped scan at %s\n\n", stopstring);  
    return ul;  
}

int Debugger::setReg(char* target, char* valStr)
{
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, m_child_pid, 0, &regs) != 0)
        errquit("getRegs ptrace(PTRACE_GETREGS)");
    reg_t val = convertStr2ul(valStr);
    if (strcmp("rip", target) == 0) regs.rip = val;
    else if (strcmp("flags", target) == 0) regs.eflags = val;
    
    else if (strcmp("rax", target) == 0) regs.rax = val;
    else if (strcmp("rbx", target) == 0) regs.rbx = val;
    else if (strcmp("rcx", target) == 0) regs.rcx = val;
    else if (strcmp("rdx", target) == 0) regs.rdx = val;

    else if (strcmp("r8", target) == 0) regs.r8 = val;
    else if (strcmp("r9", target) == 0) regs.r9 = val;
    else if (strcmp("r10", target) == 0) regs.r10 = val;
    else if (strcmp("r11", target) == 0) regs.r11 = val;

    else if (strcmp("r12", target) == 0) regs.r12 = val;
    else if (strcmp("r13", target) == 0) regs.r13 = val;
    else if (strcmp("r14", target) == 0) regs.r14 = val;
    else if (strcmp("r15", target) == 0) regs.r15 = val;

    else if (strcmp("rdi", target) == 0) regs.rdi = val;
    else if (strcmp("rsi", target) == 0) regs.rsi = val;
    else if (strcmp("rbp", target) == 0) regs.rbp = val;
    else if (strcmp("rsp", target) == 0) regs.rsp = val;
    else printf("** not find %s reg\n", target);
    
    if(ptrace(PTRACE_SETREGS, m_child_pid, 0, &regs) != 0) errquit("ptrace(SETREGS)");
    return 0;
}

int Debugger::loadProgram(string program)
{
    char * const argv[] = {NULL};
    pid_t parant_pid = getpid();
    pid_t child_pid;
    if (program == "")
        return -1;
    
    if ((child_pid = fork()) < 0)
    {
        perror("** fork");
        exit(1);
    }
    // child
    if(child_pid == 0)
    {
        // printf("** child pid %d\n", getpid());
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("** ptrace@child PTRACE_TRACEME");
        execvp(program.c_str(), argv);
        perror("** execvp");
        exit(1); 
    }
    //parant
    else
    {
        printf("** parant pid %d, child pid %d\n", getpid(), child_pid);
        m_child_pid = child_pid;
        if(waitpid(m_child_pid, &m_wait_status, 0) < 0) errquit("** waitpid");
        ptrace(PTRACE_SETOPTIONS, m_child_pid, 0, PTRACE_O_EXITKILL);
    }
    setAllBreakpoin();
    setStates(RunningStates);
    return 0;
}

int Debugger::show_vmmap()
{
    reg_t baseaddr, target, code;
    map<range_t, map_entry_t> vmmap;
    map<range_t, map_entry_t>::iterator vi;
    if(load_maps(m_child_pid, vmmap) <= 0) {
        fprintf(stderr, "** cannot load memory mappings.\n");
        return -1;
    }
    fprintf(stderr, "** %zu map entries loaded.\n", vmmap.size());

    for(vi = vmmap.begin(); vi != vmmap.end(); vi++) {
        printf("%016llx-%016llx\t%s\t%ld\t%s\n",vi->second.range.begin, vi->second.range.end, vi->second.permStr.c_str(), vi->second.offset, vi->second.name.c_str());
    }
    return 0;
}

int Debugger::load_maps(pid_t pid, map<range_t, map_entry_t>& loaded) {
	char fn[MAX_BUF_SIZE];
	char buf[MAX_BUF_SIZE];
	FILE *fp;
	snprintf(fn, sizeof(fn), "/proc/%u/maps", pid);
	if((fp = fopen(fn, "rt")) == NULL) return -1;
	while(fgets(buf, sizeof(buf), fp) != NULL) {
		int nargs = 0;
		char *token, *saveptr, *args[8], *ptr = buf;
		map_entry_t m;
		while(nargs < 8 && (token = strtok_r(ptr, " \t\n\r", &saveptr)) != NULL) {
			args[nargs++] = token;
			ptr = NULL;
		}
		if(nargs < 6) continue;
		if((ptr = strchr(args[0], '-')) != NULL) {
			*ptr = '\0';
			m.range.begin = strtoul(args[0], NULL, 16);
			m.range.end = strtoul(ptr+1, NULL, 16);
		}
		// m.name = basename(args[5]);
        m.name = args[5]; //full path
		m.perm = 0;
		if(args[1][0] == 'r') m.perm |= 0x04;
		if(args[1][1] == 'w') m.perm |= 0x02;
		if(args[1][2] == 'x') m.perm |= 0x01;
        m.permStr = "---";
        if(args[1][0] == 'r') m.permStr[0] = 'r';
		if(args[1][1] == 'w') m.permStr[1] = 'w';
		if(args[1][2] == 'x') m.permStr[2] = 'x';
		m.offset = strtol(args[2], NULL, 16);
		//printf("XXX: %lx-%lx %04o %s\n", m.range.begin, m.range.end, m.perm, m.name.c_str());
		loaded[m.range] = m;
	}
	return (int) loaded.size();
}

int Debugger::dumpCode(long code, char *msg) {
	sprintf(msg, "%02x %02x %02x %02x %02x",
		((unsigned char *) (&code))[0],
		((unsigned char *) (&code))[1],
		((unsigned char *) (&code))[2],
		((unsigned char *) (&code))[3],
		((unsigned char *) (&code))[4]);
    return 0;
}

char Debugger::char2ASCII(unsigned char c)
{
    if (c < 32 || c > 127)
    {
        return '.';
    }
    return c;
}

int Debugger::dumpCodeASCII(reg_t addr) {
    reg_t code = peek_code(addr);
    reg_t code4 = peek_code(addr + 4);
    reg_t code8 = peek_code(addr + 8);
    reg_t code12 = peek_code(addr + 12);

	printf("\t0x%llx: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        addr,
		((unsigned char *) (&code))[0],
		((unsigned char *) (&code))[1],
		((unsigned char *) (&code))[2],
		((unsigned char *) (&code))[3],
		((unsigned char *) (&code4))[0],
        ((unsigned char *) (&code4))[1],
		((unsigned char *) (&code4))[2],
		((unsigned char *) (&code4))[3],
		((unsigned char *) (&code8))[0],
		((unsigned char *) (&code8))[1],
        ((unsigned char *) (&code8))[2],
		((unsigned char *) (&code8))[3],
		((unsigned char *) (&code12))[0],
		((unsigned char *) (&code12))[1],
		((unsigned char *) (&code12))[2],
        ((unsigned char *) (&code12))[3]);
    printf("  |%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c|\n",
        char2ASCII(((unsigned char *) (&code))[0]),
        char2ASCII(((unsigned char *) (&code))[1]),
        char2ASCII(((unsigned char *) (&code))[2]),
        char2ASCII(((unsigned char *) (&code))[3]),
        char2ASCII(((unsigned char *) (&code4))[0]),
        char2ASCII(((unsigned char *) (&code4))[1]),
        char2ASCII(((unsigned char *) (&code4))[2]),
        char2ASCII(((unsigned char *) (&code4))[3]),
        char2ASCII(((unsigned char *) (&code8))[0]),
        char2ASCII(((unsigned char *) (&code8))[1]),
        char2ASCII(((unsigned char *) (&code8))[2]),
        char2ASCII(((unsigned char *) (&code8))[3]),
        char2ASCII(((unsigned char *) (&code12))[0]),
        char2ASCII(((unsigned char *) (&code12))[1]),
        char2ASCII(((unsigned char *) (&code12))[2]),
        char2ASCII(((unsigned char *) (&code12))[3])
        );
    return 0;
}

int Debugger::setBreakPoint(reg_t break_point)
{
    char msgCode[MAX_BUF_SIZE];

    if (!checkAddrInTextRange(break_point)) return 0;

    if (m_breakpoints.find(break_point) != m_breakpoints.end())
    {
        printf("** the breakpoint is already exists.\n");
        return 0;
    }

    reg_t original_code;
    // fprintf(stderr, "** entry point = 0x%zx, break point = 0x%zx.\n", m_elf_info.entry_addr, break_point);
    /* get original text: 48 39 d0 */
    original_code = peek_code(break_point);

    // dumpCode(code, msgCode);
    /* set break point */
    p_setBreakpoint(break_point);
    
    m_breakpoint_addrs.push_back(break_point);
    m_breakpoints[break_point] = original_code;
    return 0;
}

int Debugger::p_setBreakpoint(reg_t break_point)
{
    unsigned long code = peek_code(break_point);
    if(ptrace(PTRACE_POKETEXT, m_child_pid, break_point, (code & 0xffffffffffffff00) | 0xcc) != 0)
        errquit("** setBreak ptrace(POKETEXT)");
    return 0;
}

int Debugger::deleteBreak(int idx)
{
    if (idx < 0 || idx >= (int)m_breakpoint_addrs.size())
    {
        printf("** not find idx (%d).\n", idx);
        return 0;
    }
    reg_t breakpoint_addr = m_breakpoint_addrs[idx];
    /* restore break point */
    if(ptrace(PTRACE_POKETEXT, m_child_pid, breakpoint_addr, m_breakpoints[breakpoint_addr]) != 0)
        errquit("ptrace(POKETEXT)");
    m_breakpoints.erase(breakpoint_addr);
    m_breakpoint_addrs.erase(m_breakpoint_addrs.begin() + idx);
    return 0;
}

int Debugger::recoverBeackpoint(struct user_regs_struct regs)
{ 
    map<reg_t, reg_t>::iterator iter;
    iter = m_breakpoints.find(regs.rip);
    printf("** recoverBeackpoint %llx\n", regs.rip);
    if(iter != m_breakpoints.end()){
        reg_t target, code;
        target = iter->first;
        code = iter->second;
        /* restore break point */
        if(ptrace(PTRACE_POKETEXT, m_child_pid, target, code) != 0)
            errquit("** ptrace(POKETEXT)");
    }
    return 0;
}


int Debugger::checkProgramState(reg_t before_rip)
{
    // printf("** wait_status = %d,  (%x)\n", m_wait_status, m_wait_status);
    if (WIFEXITED(m_wait_status))
    {
        printf("** child process %d terminiated normally (code %x)\n", m_child_pid, m_wait_status);
        // if (loadProgram(m_program) != 0) errquit("**loadProgram");
        setStates(LoadedStates);
    }
    else if (WIFSTOPPED(m_wait_status))
    {
        struct user_regs_struct regs;
        getReg(&regs);
        map<reg_t, reg_t>::iterator iter_before;
        iter_before = m_breakpoints.find(before_rip);
        if(iter_before != m_breakpoints.end()){
            p_setBreakpoint(iter_before->first);
		}
        map<reg_t, reg_t>::iterator iter;
        iter = m_breakpoints.find(regs.rip-1);
        if(iter != m_breakpoints.end()){
            char codeMsg[MAX_BUF_SIZE];
            dumpCode(iter->second, codeMsg);
            printf("** breakpoint @ \t 0x%llx: %s\tmov\tebx,1\n", iter->first, codeMsg);
            /* set registers */
            regs.rip = regs.rip-1;
            // regs.rdx = regs.rax;
            if(ptrace(PTRACE_SETREGS, m_child_pid, 0, &regs) != 0) errquit("ptrace(SETREGS)");
		}
        setStates(RunningStates);
        printf("** child process %d stop (code %x)\n", m_child_pid, m_wait_status);
    }
    return 0;
}

int Debugger::bufferToCmds(char *buf, vector<string> *cmds)
{
    
    int cmdCount = 0;
    if (buf == NULL) return ERR;
    buf[strcspn(buf, "\n")] = 0;
    char *token = strtok(buf, " ");
    std::string tokenStr;
    while(token != NULL)
    {
        tokenStr.assign(token, strlen(token));
        cmds->push_back(tokenStr);
        cmdCount++;
        token = strtok(NULL, " ");
        // printf("token = %s cmdCount = %d %s\n", token, cmdCount, tokenStr.c_str());
    }
    return cmdCount;
}

int Debugger::runByStdin()
{
    int ret = 0;
    char buffer[MAX_BUF_SIZE];
    while (ret >= 0)
    {
        printf("sdb>");
        fgets(buffer, MAX_BUF_SIZE, stdin);
        vector<string> cmds;
        int count = bufferToCmds(buffer, &cmds);
        ret = doCommand(&cmds);
    }
    return 0;
}

int Debugger::runByScript()
{
    char buffer[MAX_BUF_SIZE];
    int ret = 0;
    FILE *fp;
    fp = fopen(m_script.c_str(), "r");
    
    if (fp != NULL) {
        while (fgets(buffer, MAX_BUF_SIZE, fp) != NULL) {
            printf("** script>%s", buffer);
            vector<string> cmds;
            int count = bufferToCmds(buffer, &cmds);
            ret = doCommand(&cmds);
        }
        // printf("** close file\n");
        fclose(fp);
    } else
        printf("** failed to open '%s' file.\n", m_script.c_str());

    return 0;
}


int Debugger::readELF(string program)
{
    FILE * pFile = NULL;
    pFile = fopen(program.c_str(), "r");
    if (pFile == NULL) errquit("** fopen");

    // check if elf file
    char elf_head[5] = {};
    fread(elf_head, 1, 5, pFile);
    if (elf_head[0] != 0x7F || elf_head[1] != 'E' || elf_head[2] != 'L' || elf_head[3] != 'F')
    {
        fprintf(stdout, "** if not elf file %s\n", program.c_str());
        return ERR;
    }
    elf_type = (int)elf_head[4];

    // get m_elf_header
    if (elf_type == ELF_32_BIT_TYPE)
    {   
        printf("** 32 bit\n");
        fseek(pFile, 0, SEEK_SET);
        fread(&m_elf_header32, 1, sizeof(Elf32_Ehdr), pFile);

        fseek(pFile, m_elf_header32.e_shoff + m_elf_header32.e_shstrndx * sizeof(Elf32_Shdr), SEEK_SET);
        fread(&m_sh_table32, 1, sizeof(Elf32_Shdr), pFile);
        m_elf_info.entry_addr = (unsigned long)m_elf_header32.e_entry;
        fprintf(stdout, "** program '%s' loaded. entry point 0x%llx\n", program.c_str(), m_elf_info.entry_addr);
        char SectNames[MAX_BUF_SIZE] = "";
        if (m_sh_table32.sh_size > MAX_BUF_SIZE) printf("** m_sh_table32.sh_size > MAX_BUF_SIZE\n");
        fseek(pFile, m_sh_table32.sh_offset, SEEK_SET);
        fread(SectNames, 1, m_sh_table32.sh_size, pFile);

        for (int idx = 0; idx < m_elf_header32.e_shnum; idx++)
        {
            const char* name = "";
            
            fseek(pFile, m_elf_header32.e_shoff + idx * sizeof(Elf32_Shdr), SEEK_SET);
            fread(&m_sh_table32, 1, sizeof(Elf32_Shdr), pFile);

            // print section name
            if (m_sh_table32.sh_name){
                name = SectNames + m_sh_table32.sh_name;
                if (strcmp(".text", name) == 0)
                {
                    fprintf(stdout, "** section idx = %2u name = '%s' size 0x%lx\n", idx, name, (unsigned long)m_sh_table32.sh_size);
                    m_elf_info.text_size = (unsigned long)m_sh_table32.sh_size;
                    m_elf_info.text_min_addr = m_elf_info.entry_addr;
                    m_elf_info.text_max_addr = m_elf_info.entry_addr + (unsigned long)m_sh_table32.sh_size;
                    break;
                }
            }
        }
    }
    else if (elf_type == ELF_64_BIT_TYPE)
    {
        printf("** 64 bit\n");
        fseek(pFile, 0, SEEK_SET);
        fread(&m_elf_header64, 1, sizeof(Elf64_Ehdr), pFile);

        fseek(pFile, m_elf_header64.e_shoff + m_elf_header64.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
        fread(&m_sh_table64, 1, sizeof(Elf64_Shdr), pFile);
        m_elf_info.entry_addr = (unsigned long)m_elf_header64.e_entry;
        fprintf(stdout, "** program '%s' loaded. entry point 0x%llx\n", program.c_str(), m_elf_info.entry_addr);
        char SectNames[MAX_BUF_SIZE] = "";
        fseek(pFile, m_sh_table64.sh_offset, SEEK_SET);
        if (m_sh_table64.sh_size > MAX_BUF_SIZE) printf("** m_sh_table64.sh_size > MAX_BUF_SIZE\n");
        fread(SectNames, 1, m_sh_table64.sh_size, pFile);

        for (int idx = 0; idx < m_elf_header64.e_shnum; idx++)
        {
            const char* name = "";
            
            fseek(pFile, m_elf_header64.e_shoff + idx * sizeof(Elf64_Shdr), SEEK_SET);
            fread(&m_sh_table64, 1, sizeof(Elf64_Shdr), pFile);

            // print section name
            if (m_sh_table64.sh_name){
                name = SectNames + m_sh_table64.sh_name;
                if (strcmp(".text", name) == 0)
                {
                    fprintf(stdout, "** section idx = %2u name = '%s' size 0x%lx\n", idx, name, m_sh_table64.sh_size);
                    m_elf_info.text_size = (unsigned long)m_sh_table64.sh_size;
                    m_elf_info.text_min_addr = m_elf_info.entry_addr;
                    m_elf_info.text_max_addr = m_elf_info.entry_addr +  (unsigned long)m_sh_table64.sh_size;
                    break;
                }
            }
        }
    }
    else
    {
        fprintf(stdout, "** unknown elf type (invalid class '0', 32-bit '1', 64-bit '2') %d\n", elf_type);
    }
    if (init_disasm() != 0) errquit("** cshandle");
    setStates(LoadedStates);
    fclose(pFile);
    return 0;
}

States Debugger::setStates(States newStates)
{
    States oldStates = m_states;
    m_states = newStates;
    return oldStates;
}

States Debugger::getStates()
{
    return m_states;
}

int Debugger::disasm(int instructionsCount, reg_t addr)
{
    unsigned long offect = 0;
    if (!checkAddrInTextRange(addr))
    {
        fprintf(stdout, "** the address is out of the range of the text segment\n");
        return 0;
    }
    for (unsigned long i = 0; i < MAX_DUMP_INSTRUCTIONS; ++i)
    {   
        if (!checkAddrInTextRange(addr + offect))
        {
            fprintf(stdout, "** the address is out of the range of the text segment\n");
            break;
        }
        unsigned long ret = disassemble(m_child_pid, addr + offect);
        offect += ret;    
        // printf("** offect %ld, ret %ld,  m_sh_table.sh_size %ld\n",offect, ret, m_elf_info.text_size);
        // printf("** min 0x%lx, max 0x%lx, size %ld\n",m_elf_info.text_min_addr, m_elf_info.text_max_addr, m_elf_info.text_size);
    }   
    return 0;
}

int Debugger::init_disasm()
{
    if (elf_type == ELF_32_BIT_TYPE)
    {
        if(cs_open(CS_ARCH_X86, CS_MODE_32, &cshandle) != CS_ERR_OK)
        {
            return -1;
        }
    }
    else if (elf_type == ELF_64_BIT_TYPE)
    {
        if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
        {
            return -1;
        }
    }
    
    // printf("** cshandle %ld\n", cshandle);
    return 0;
}

int Debugger::close_disasm()
{
    cs_close(&cshandle);
    return 0;
}

void Debugger::print_instruction(long long addr, instruction *in) {
	int i;
	char bytes[MAX_BUF_SIZE] = "";
	if(in == NULL) {
		fprintf(stdout, "\t%06llx:\t<cannot disassemble>\n", addr);
	} else {
		for(i = 0; i < in->size; i++) {
			snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
		}
		fprintf(stdout, "\t%06llx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(), in->opnd.c_str());
	}
}

unsigned long Debugger::disassemble(pid_t proc, unsigned long long rip) {
	int count;
	char buf[64] = { 0 };
	unsigned long long ptr = rip;
	cs_insn *insn;
	map<long long, instruction>::iterator mi; // from memory addr to instruction

	if((mi = instructions.find(rip)) != instructions.end()) {
		print_instruction(rip, &mi->second);
        return mi->second.size;
	}
    
	for(ptr = rip; ptr < rip + sizeof(buf); ptr += PEEKSIZE) {
		reg_t peek;
		errno = 0;
        if (checkBreakpoint(ptr))
        {
            peek = m_breakpoints[ptr];
            memcpy(&buf[ptr-rip], &peek, PEEKSIZE);
        }
        else
        {
            peek = peek_code(ptr);
            if(errno != 0) break;
            memcpy(&buf[ptr-rip], &peek, PEEKSIZE);
        }		
	}
	if(ptr == rip)  {
		print_instruction(rip, NULL);
		return 0;
	}
    
    // printf("cs_disasm cshandle %ld\n", cshandle);
	
    if((count = cs_disasm(cshandle, (uint8_t*) buf, rip-ptr, rip, 0, &insn)) > 0) {
		int i;
		for(i = 0; i < count; i++) {
			instruction in;
			in.size = insn[i].size;
			in.opr  = insn[i].mnemonic;
			in.opnd = insn[i].op_str;
			memcpy(in.bytes, insn[i].bytes, insn[i].size);
			instructions[insn[i].address] = in;
		}
		cs_free(insn, count);
	}
    
	if((mi = instructions.find(rip)) != instructions.end()) {
		print_instruction(rip, &mi->second);
        return mi->second.size;
	} else {
		print_instruction(rip, NULL);
        return 0;
	}
    
	return 0;
}

int Debugger::dump(reg_t addr)
{
    reg_t code, code4, code8, code12;
    if (!checkAddrInTextRange(addr))
    {
        fprintf(stdout, "** the address is out of the range of the text segment\n");
        return 0;
    }
    for (int offset = 0; offset < 80; offset += DUMP_SIZE)
    {
        dumpCodeASCII(addr + offset);
    }
    return 0;
}

reg_t Debugger::peek_code(reg_t addr)
{
    reg_t code = ptrace(PTRACE_PEEKTEXT, m_child_pid, addr, 0);
    return code;
}

bool Debugger::checkBreakpoint(reg_t break_point)
{
    return m_breakpoints.find(break_point) != m_breakpoints.end();
}

bool Debugger::checkAddrInTextRange(reg_t addr)
{
    if (addr >= m_elf_info.text_min_addr && addr < m_elf_info.text_max_addr)
    {
        return true;
    }
    return false;
}

int Debugger::setAllBreakpoin()
{
    for( map<reg_t,reg_t>::iterator iter=m_breakpoints.begin(); iter!=m_breakpoints.end(); ++iter)  
    {  
        auto beackAddr = (*iter).first;
        p_setBreakpoint(beackAddr);
    }
    return 0;
}