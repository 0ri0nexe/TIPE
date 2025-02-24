#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    pid_t child;
    struct user_regs_struct regs;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program_to_debug> <>\n", argv[0]);
        return 1;
    }

    child = fork();
    if (child == 0) {
        
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
    } else {
        
        int status;
        waitpid(child, &status, 0);  
        ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);

        while (WIFSTOPPED(status)) {
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            printf("Next instruction at: %llx\n", regs.rip);

            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            waitpid(child, &status, 0);  
        }

        printf("Processus terminé.\n");
    }

    return 0;
}
