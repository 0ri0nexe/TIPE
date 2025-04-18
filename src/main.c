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

// fork child process 
pid_t give_birth(char* name) {
    pid_t child = fork();
    if (child == -1) {
        error_exit("fork");
    }

    if (child == 0) {
        // Enfant : demande à être tracé
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);  // Laisser le parent se préparer
        execvp(name, &name);
        error_exit("execvp"); // Ne devrait pas arriver
    }
    return child;
}

int execute(int steps, pid_t child, int* status) {
    for (int i = 0; i < steps; i--) {

        if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) == -1)
            error_exit("ptrace SINGLESTEP");
            
        waitpid(child, status, 0);
        if (WIFEXITED(*status) || WIFSIGNALED(*status)) {
            printf("Child exited.\n");
            return true;
        }
    }
    return false;
}

void readm(pid_t child, struct user_regs_struct* regs, uint8_t* code) {
    for (int i = 0; i < MAX_INSN_BYTES; i += sizeof(long)) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKTEXT, child, regs->rip + i, 0);
        if (data == -1 && errno != 0)
            error_exit("ptrace PEEKTEXT");

        memcpy(&code[i], &data, sizeof(long));
    }
}

void handle_insn(bool* cmp, bool* jmp, uint64_t* jmp_adress, cs_insn* insn, struct user_regs_struct* regs) {
    if (cmp) {
        if (*cmp && *jmp) {
            if (*jmp_adress == regs->rip) {
                printf("0x%lx 1\n", insn[0].address);
            } else {
                printf("0x%lx 0\n", insn[0].address);
            }
            *cmp = false;
            *jmp = false;
        }

        if (strstr(insn->mnemonic, "j")) {
            *jmp = true;
            *jmp_adress = (uint64_t)strtol(insn->op_str, NULL, 0);
        } else {
            fprintf(stderr, "No jmp instruction after cmp");
            *cmp = false;
            *jmp = false;
        } 
        
    } else if (strstr(insn->mnemonic, "cmp")) {
        *cmp = true;
    }
}

int run_child(pid_t child) {
    
    int status;
    struct user_regs_struct regs; // Process parameters

    waitpid(child, &status, 0); // Waiting for SIGSTOP
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

    // Capstone initialisation
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return 1;
    }

    // mainloop
    bool stop = false;
    bool cmp  = false;
    bool jmp  = false;
    uint64_t jmp_adress;
    while (!stop) {
        // Collecting current process settings
        if (ptrace(PTRACE_GETREGS, child, 0, &regs) == -1)
            error_exit("ptrace GETREGS");

        // Reading RIP register
        uint8_t code[MAX_INSN_BYTES];
        readm(child, &regs, code);

        // Disassemble the instruction at RIP adress
        count = cs_disasm(handle, code, MAX_INSN_BYTES, regs.rip, 1, &insn);
        
        // TODO Handle asm sorting 
        if (count > 0) {
            handle_insn(&cmp, &jmp, &jmp_adress, insn, &regs);
            cs_free(insn, count);
        } else {
            fprintf(stderr, "0x%llx:\t<unable to disassemble>\n", regs.rip);
            return 1;
        }

        // Exécuter l'instruction
        stop = execute(1, child, &status);
    }

    cs_close(&handle);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <executable> [args...]\n", argv[0]);
        return 1;
    }

    pid_t child = give_birth(argv[1]);
    run_child(child);

}
