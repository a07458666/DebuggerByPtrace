#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <iostream>
#include <map>
#include <cstring>

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

Debugger::Debugger(char * script, char* program)
{
    m_states = NotLoadedStates;
    m_program = program;
    if (strcmp(program, "") != 0) 
    {
        int ret = loadProgram(program);
        if (ret != 0) errquit("**loadProgram");
    }
}

Debugger::~Debugger(){}

int Debugger::getRegs()
{

    return 0;
}

int Debugger::getCommand()
{
    int wait_status;
    char inputCmd[128];
    int ret = 0;

    cout << "sdb>";
    cin >> inputCmd;

    if (strcmp("load", inputCmd) == 0)
    {   
        char program[128];
        cin >> program;
        if(m_states == NotLoadedStates)
        {
            int ret = loadProgram(program);
            if (ret != 0) errquit("**loadProgram");
            m_states = LoadedStates;
        }
        else
        {
            printf("**states is loaded\n");
        }
    }
    else if (strcmp("start", inputCmd) == 0)
    {
        if (m_states == LoadedStates)
        {
            printf("** pid %d\n", m_child_pid);
            m_states = RunningStates;
        }
    }
    else if (strcmp("run", inputCmd) == 0 || strcmp("r", inputCmd) == 0)
    {
        if (m_states == RunningStates)
        {
            printf("** program %s is already running\n", m_program);
            m_states = RunningStates;
            cont();
        }
        else if (m_states == LoadedStates)
        {
            printf("** run program %s\n", m_program);
            cont();
        }
    }
    else if (strcmp("cont", inputCmd) == 0 || strcmp("c", inputCmd) == 0)
    {
        if (m_states == RunningStates)
        {
            cont();
        }
    }
    else if (strcmp("si", inputCmd) == 0)
    {
        if (m_states == RunningStates)
        {
            step();
        }
    }
    else if (strcmp("vmmap", inputCmd) == 0)
    {
        if (m_states == RunningStates)
        {
            if(show_vmmap() < 0) errquit("** show_vmmap");
        }
    }
    else if (strcmp("exit", inputCmd) == 0 || strcmp("q", inputCmd) == 0)
    {
        printf("**exit\n");
        ret = -1;
    }
    else if(strcmp("help", inputCmd) == 0 || strcmp("h", inputCmd) == 0)
    {
        printf(HELP_MGS);
    }
    else
    {
        printf("**not define cmd %s\n", inputCmd);
    }
    return ret;
}

int Debugger::cont()
{
    int wait_status;
    if(ptrace(PTRACE_CONT, m_child_pid,0 ,0) < 0) errquit("**ptrace@cont");
    if(waitpid(m_child_pid, &wait_status, 0) < 0) errquit("**waitpid");
}

int Debugger::trace()
{
    int wait_status;
    unsigned long baseaddr, target, code;
    map<range_t, map_entry_t> vmmap;
    map<range_t, map_entry_t>::iterator vi;

    if(waitpid(m_child_pid, &wait_status, 0) < 0) errquit("**waitpid");
    while (WIFSTOPPED(wait_status) > 0)
    {   
        struct user_regs_struct regs;
        // getCommand();
        if (ptrace(PTRACE_SINGLESTEP, m_child_pid, 0, 0) < 0) errquit("** ptrace@STEP");
        if (waitpid(m_child_pid, &wait_status, 0) < 0) errquit("** waitpid@child_pid");
    }
    return 0;
}

// cmd si
int Debugger::step()
{
    int wait_status;
    if (ptrace(PTRACE_SINGLESTEP, m_child_pid, 0, 0) < 0) errquit("** ptrace@STEP");
    if (waitpid(m_child_pid, &wait_status, 0) < 0) errquit("** setp");
    return 0;
}


int Debugger::setBreakPoint()
{
    /* set break point */
    // if(ptrace(PTRACE_POKETEXT, m_child_pid, target, (code & 0xffffffffffffff00) | 0xcc) != 0) 
    //     errquit("** setBreakPoint ptrace(POKETEXT)");
}

int Debugger::loadProgram(char* program)
{
    char * const argv[] = {NULL};
    pid_t parant_pid = getpid();
    pid_t child_pid;
    int wait_status;
    printf("**[trace] program = %s\n", program);
    if (program == NULL)
        return -1;
    
    if ((child_pid = fork()) < 0)
    {
        perror("**fork");
        exit(1);
    }
    // child
    if(child_pid == 0)
    {
        printf("**child pid %d\n", getpid());
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("**ptrace@child PTRACE_TRACEME");
        execvp(program, argv);
        perror("**execvp");
        exit(1); 
    }
    //parant
    else
    {
        printf("**parant pid %d, child pid %d\n", getpid(), child_pid);
        m_child_pid = child_pid;
        if(waitpid(m_child_pid, &wait_status, 0) < 0) errquit("**waitpid");
        ptrace(PTRACE_SETOPTIONS, m_child_pid, 0, PTRACE_O_EXITKILL);
    }
    m_states = LoadedStates;
    return 0;
}

void Debugger::dumpCode(long addr, long code) {
	fprintf(stderr, "## %lx: code = %02x %02x %02x %02x %02x %02x %02x %02x\n",
		addr,
		((unsigned char *) (&code))[0],
		((unsigned char *) (&code))[1],
		((unsigned char *) (&code))[2],
		((unsigned char *) (&code))[3],
		((unsigned char *) (&code))[4],
		((unsigned char *) (&code))[5],
		((unsigned char *) (&code))[6],
		((unsigned char *) (&code))[7]);
}

int Debugger::show_vmmap()
{
    unsigned long baseaddr, target, code;
    map<range_t, map_entry_t> vmmap;
    map<range_t, map_entry_t>::iterator vi;
    if(load_maps(m_child_pid, vmmap) <= 0) {
        fprintf(stderr, "** cannot load memory mappings.\n");
        return -1;
    }
    fprintf(stderr, "** %zu map entries loaded.\n", vmmap.size());

    for(vi = vmmap.begin(); vi != vmmap.end(); vi++) {
        printf("%016lx-%016lx\t%s\t%ld\t%s\n",vi->second.range.begin, vi->second.range.end, vi->second.permStr.c_str(), vi->second.offset, vi->second.name.c_str());
    }
    return 0;
}

int Debugger::load_maps(pid_t pid, map<range_t, map_entry_t>& loaded) {
	char fn[128];
	char buf[256];
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
			m.range.begin = strtol(args[0], NULL, 16);
			m.range.end = strtol(ptr+1, NULL, 16);
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

int Debugger::run()
{
    int cmd = 0;
    while((cmd = getCommand()) >= 0)
    {
        // printf("**run() cmd %d\n", cmd);
    }
    return 0;
}