#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

int get_adresses(int argc, char *argv[]) {
    pid_t child;
    struct user_regs_struct regs;

    child = fork();
    if (child == 0) {
        // Processus enfant : Se prépare pour être tracé
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
    } else {
        // Processus parent : Débogueur
        int status;
        waitpid(child, &status, 0);  // Attend que l'enfant soit stoppé
        ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);  // Démarre l'exécution

        while (WIFSTOPPED(status)) {
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            printf("Next instruction at: %llx\n", regs.rip);  // Affiche RIP

            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);  // Exécute une instruction
            waitpid(child, &status, 0);  // Attend la fin de l'instruction
        }

        printf("Processus terminé.\n");
    }

    return 0;
}
