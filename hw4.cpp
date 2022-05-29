#include <stdio.h>
#include <getopt.h>
#include <string>
#include <vector>
#include <cstring>
#include <getopt.h>

#include "debugger.h"

int getOptScript(int argc, char* argv[], char* script, char* program)
{
    int flags, opt;
    int nsecs, tfnd;
    int idx;
    std::string filter;
    nsecs = 0;
    tfnd = 0;
    while ((opt = getopt(argc, argv, "s:")) != -1) {
        switch (opt) 
        {
            case 's':
                strcpy (script, optarg);
                break;
            default: /* '?' */
                fprintf(stderr, "usage: %s [-s script] [program]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    for (idx = optind; idx < argc; idx++)
        strcpy (program, argv[idx]);
    return 0;
}

int main(int argc, char* argv[])
{
    char script[128] = "";
    char program[128] = "";
    int err = getOptScript(argc, argv, script, program);
    // printf("**-s script =  %s\n", script);
    // printf("**program =  %s\n", program);
    if (err == -1) return err;
    
    long offset = 0x9cc; // the default value we reverse engineered
	offset = strtol(program, NULL, 0);
	fprintf(stderr, "## offset = %ld (0x%lx)\n", offset, offset);

    Debugger debugger = Debugger(script, program);
    debugger.run();
    return 0;
}