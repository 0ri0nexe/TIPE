# TIPE

## Introcution

A work for my project on processor's branch prediction algorithm.

The use of this repo might change in the future, for now its goal is to extract conditionnal jumps taken by a program at execution in order to get real numbers from actual programs in order to benchmark different branch prediction algorithms.

> [!WARNING]  
> This project is ONLY for amd64 processor architectures and will probably not work for anything else.

## Compiling

### With Make

Place yourself in the root of the project and execute

```makefile
make
```
### With GCC

In the root of the project, execute :
```bash
gcc -o [name_of_the_executable_you_want] ./src/main.c
```

## Usage

Use the following command to use the executable (replace ./bin/bench with your own path to the executable if you compiled with other method than make):
```
./bin/bench <path_to_the_executable> <path_to_the_output_file> [args...] 
```

## Aguments

Here are the arguments you can put (only one for now) :

 - `-v` or `--verbose` : print the number of lines which couldn't be disassemble for some reason (if the executable you are auditing is printing something, it isn't gonna be disassemblable) and the number of flag setter that arren't followed by a jump : this is the number of times that the program ran on a flag setter instruction (cmp and test) and these conditions weren't followed by a jump instruction (jmp, je, jle, ...), in which case the flag setter is considered useless. 

## output file format
A line of the output file is formated this way :

```
jump_adress jump_taken
```

With jump adress  

## Method

The method used here is to execute the program and extract all the instruction it goes through. This is done by executing the program step by step and in a step :
 - Collect the successive adresses taken by the RIP register (instruction pointer register)
  
 - Disassemble the first instruction in memory at this adress

We have a list of adresses and instruction, then we need to detect conditional jumps, to do so, we search for a "cmp" condition, followed by a jump instruction (je, jz, jg, ...). The mnemotic is followed by an adress, it's the jump adress. By comparing the jump adress with the adress taken by RIP in the next step, we can deduct if the jump was taken or not.

## Dependencies

- **capstone** : Used to disassemble the executable.

## TODO

Handling the argument passing to the executable.

## Journal de bord :

--> 11/04/2025 : program trace of programs done.

--> 18/04/2025 : refactoring code (now beautiful)

--> 09/05/2025 : jump condition sucessfully detected and written into the output file. Error handling is pretty good, added a "verbose" argument.