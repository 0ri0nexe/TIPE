#define  _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>   // For struct user_regs_struct
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
        // An error occurred forking the child
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP); 
        execvp(name, &name);
        error_exit("execvp");
    }
    return child;
}

int execute(int steps, pid_t child, int* status) {
    for (int i = 0; i < steps; i++) {

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

void handle_insn(bool* cmp, bool* jmp, uint64_t* jmp_adress, cs_insn* insn, struct user_regs_struct* regs, FILE* output_file, int* flag_setter_not_linked) {
    if (strcmp(insn[0].mnemonic, "cmp") == 0 || strcmp(insn[0].mnemonic, "test") == 0) {
        *cmp = true;
    } else if (strstr(insn[0].mnemonic, "j")) {
        *jmp = true;
        *jmp_adress = strtoull(insn[0].op_str, NULL, 16);
    } else if (*cmp && *jmp) {
        fprintf(output_file, "0x%lx\t%d\n", *jmp_adress, *jmp_adress == regs->rip);
        *jmp = false;
        *jmp_adress = false;
    } else if (cmp && !jmp) {
        (*flag_setter_not_linked)++;
    } else {
        *jmp = false;
        *cmp = false;
    }

}

int run_child(pid_t child, FILE* output_file, bool verbose) {
    
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

    int flag_setter_not_liked = 0;
    int undisassembled_lines = 0;
    
    while (!stop) {
        // Collecting current process settings
        if (ptrace(PTRACE_GETREGS, child, 0, &regs) == -1)
            error_exit("ptrace GETREGS");

        // Reading RIP register
        uint8_t code[MAX_INSN_BYTES];
        readm(child, &regs, code);

        // Disassemble the instruction at RIP adress
        count = cs_disasm(handle, code, MAX_INSN_BYTES, regs.rip, 1, &insn);

        if (count > 0) {
            handle_insn(&cmp, &jmp, &jmp_adress, insn, &regs, output_file, &flag_setter_not_liked);
            cs_free(insn, count);
        } else {
            undisassembled_lines++;
        }

        // Execute 1 instruction
        stop = execute(1, child, &status);
    }

    if (verbose) {
        printf("Number of undisassembled lines: %d\n", undisassembled_lines);
        printf("Number of flag setters not linked: %d\n", flag_setter_not_liked);
    }

    cs_close(&handle);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <executable> <output file> [args...]\n", argv[0]);
        return 1;
    }

    FILE* output_file = fopen(argv[2], "w");
    if (output_file == NULL) {
        fprintf(stderr, "Error opening output file: %s\n", strerror(errno));
        return 1;
    }

    bool verbose = false;

    if (argc > 3) {
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
                verbose = true;
            }
        }
    }

    pid_t child = give_birth(argv[1]);
    run_child(child, output_file, verbose);

}
