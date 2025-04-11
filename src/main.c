#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>   // Pour struct user_regs_struct
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <capstone/capstone.h>

#define MAX_INSN_BYTES 16  // Taille max d'une instruction x86_64

void error_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <executable> [args...]\n", argv[0]);
        return 1;
    }

    pid_t child = fork();
    if (child == -1) {
        error_exit("fork");
    }

    if (child == 0) {
        // Enfant : demande à être tracé
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);  // Laisser le parent se préparer
        execvp(argv[1], &argv[1]);
        error_exit("execvp"); // Ne devrait pas arriver
    } else {
        // Parent : traceur
        int status;
        struct user_regs_struct regs;

        waitpid(child, &status, 0); // Attente du SIGSTOP
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        // Initialisation de Capstone
        csh handle;
        cs_insn *insn;
        size_t count;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            fprintf(stderr, "Failed to initialize Capstone\n");
            return 1;
        }

        while (1) {
            // Lire les registres pour obtenir RIP
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) == -1)
                error_exit("ptrace GETREGS");

            // Lire les octets à l'adresse RIP
            uint8_t code[MAX_INSN_BYTES];
            for (int i = 0; i < MAX_INSN_BYTES; i += sizeof(long)) {
                errno = 0;
                long data = ptrace(PTRACE_PEEKTEXT, child, regs.rip + i, 0);
                if (data == -1 && errno != 0)
                    error_exit("ptrace PEEKTEXT");

                memcpy(&code[i], &data, sizeof(long));
            }

            // Désassembler
            count = cs_disasm(handle, code, MAX_INSN_BYTES, regs.rip, 1, &insn);
            if (count > 0) {
                printf("0x%lx:\t%s\t%s\n",
                       insn[0].address,
                       insn[0].mnemonic,
                       insn[0].op_str);
                cs_free(insn, count);
            } else {
                printf("0x%llx:\t<unable to disassemble>\n", regs.rip);
            }

            // Exécuter l'instruction
            if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) == -1)
                error_exit("ptrace SINGLESTEP");

            waitpid(child, &status, 0);
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                printf("Child exited.\n");
                break;
            }
        }

        cs_close(&handle);
    }

    return 0;
}
