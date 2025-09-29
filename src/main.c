#define  _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>   // For struct user_regs_struct
#include <string.h>
#include <limits.h>       //For PATH_MAX
#include <errno.h>
#include <capstone/capstone.h>

#define MAX_INSN_BYTES 16  // Max size of instruction bytes to read

char *resolve_path(const char *base, const char *path) {
    char combined[PATH_MAX];
    char *resolved = malloc(PATH_MAX);
    if (!resolved) return NULL;

    if (path[0] == '/') {
        // Absolute path
        if (realpath(path, resolved) == NULL) {
            free(resolved);
            return NULL;
        }
    } else {
        // Relatve path
        snprintf(combined, sizeof(combined), "%s/%s", base, path);
        if (realpath(combined, resolved) == NULL) {
            free(resolved);
            return NULL;
        }
    }
    return resolved; // Caller needs to free()
}

void error_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// Ajout d'un paramètre supplémentaire pour create_process
pid_t create_process(char* argv[], bool analyze_output) {
    pid_t child = fork();
    if (child == -1) {
        error_exit("fork");
    }

    if (child == 0) {
        // Child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP); 

        if (!analyze_output) {
            // Construit la commande avec redirection
            size_t cmd_len = 0;
            for (int i = 0; argv[i] != NULL; i++) {
                cmd_len += strlen(argv[i]) + 1;
            }
            cmd_len += strlen("> /dev/null 2>&1") + 1;

            char* command = malloc(cmd_len);
            if (!command) error_exit("malloc");

            command[0] = '\0';
            for (int i = 0; argv[i] != NULL; i++) {
                strcat(command, argv[i]);
                if (argv[i+1] != NULL) strcat(command, " ");
            }
            strcat(command, " > /dev/null 2>&1");

            execl("/bin/sh", "sh", "-c", command, NULL);
            error_exit("execl");
        } else {
            execvp(argv[0], argv);
            error_exit("execvp");
        }
    }
    return child;
}

// Execute the specified number of steps in the child process
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

// Read memory from the child process at the specified RIP address
void readm(pid_t child, struct user_regs_struct* regs, uint8_t* code) {
    for (int i = 0; i < MAX_INSN_BYTES; i += sizeof(long)) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKTEXT, child, regs->rip + i, 0);
        if (data == -1 && errno != 0){
            error_exit("ptrace PEEKTEXT");
        }
        memcpy(&code[i], &data, sizeof(long));
    }
}

// Handle the disassembled instruction and check for cmp/jmp instructions
void handle_insn(bool* cmp, bool* jmp, uint64_t* jmp_adress, uint64_t* cmp_adress, cs_insn* insn, struct user_regs_struct* regs, FILE* output_file, int* flag_setter_not_linked) {
    if (strcmp(insn[0].mnemonic, "cmp") == 0 || strcmp(insn[0].mnemonic, "test") == 0) {
        *cmp = true;
    } else if (strstr(insn[0].mnemonic, "j")) {
        *jmp = true;
        *cmp_adress=regs->rip;
        *jmp_adress = insn->detail->x86.operands[0].imm;
    } else if (*cmp && *jmp) {
        fprintf(output_file, "0x%lx\t%d\n", *cmp_adress, *jmp_adress == regs->rip);
        *jmp = false;
        *jmp_adress = false;
    } else if (cmp && !jmp) {
        (*flag_setter_not_linked)++;
    } else {
        *jmp = false;
        *cmp = false;
    }
}

// Run the child process and handle the disassembly and execution
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
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // mainloop
    bool stop = false;
    bool cmp  = false;
    bool jmp  = false;
    uint64_t jmp_adress;
    uint64_t cmp_adress;

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
            handle_insn(&cmp, &jmp, &jmp_adress, &cmp_adress, insn, &regs, output_file, &flag_setter_not_liked);
            cs_free(insn, count);
        } else {
            undisassembled_lines++;
        }

        // Execute 1 instruction
        stop = execute(1, child, &status);
    }

    if (verbose) {
        printf("\nNumber of undisassembled lines: %d\n", undisassembled_lines);
        printf("Number of flag setters not linked: %d\n", flag_setter_not_liked);
    }

    cs_close(&handle);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <executable> <output file> [options...] [-- <args for executable>]\n", argv[0]);
        return 1;
    }

    FILE* output_file = fopen(argv[2], "w");
    if (output_file == NULL) {
        fprintf(stderr, "Error opening output file: %s\n", strerror(errno));
        return 1;
    }

    bool verbose = false;
    bool analyze_output = false;
    int i = 3;
    int separator_index = -1;

    // Search for '--' and handle options
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            separator_index = i;
            break;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-a") == 0) {
            analyze_output = true;
        }
    }


    // Target executable arguments
    char** target_argv;
    int target_argc;

    if (separator_index != -1) {
        // There is arguments for the executable
        target_argc = argc - separator_index;
        target_argv = (char**)malloc((target_argc) * sizeof(char*));
        
        // The first arg is the executable name
        target_argv[0] = argv[1];
        
        // copy all the other arguments after '--'
        for (i = 1; i < target_argc; i++) {
            target_argv[i] = argv[separator_index + i];
        }
    } else {   
        // No additional arguments
        target_argc = 2;
        target_argv = (char**)malloc(target_argc * sizeof(char*));
        target_argv[0] = argv[1];
        target_argv[1] = NULL;
    }
    pid_t child = create_process(target_argv, analyze_output);

    int result = run_child(child, output_file, verbose);

    free(target_argv);
    fclose(output_file);

    if (verbose) {
        char* cwd = getcwd(NULL, 0);
        char* final_path = resolve_path(cwd, argv[2]);
        printf("Program finished without error, trace generated in %s\n", final_path);
        free(final_path);
    }
    
    return result;
}

