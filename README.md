# TIPE

## Introcution

A work for my project on processor's branch prediction algorithm.

The use of this repo might change in the future, for now its goal is to extract conditionnal jumps taken by a program at execution in order to get real numbers from actual programs to then benchmark different branch prediction technics.

## Method

To do so we need to execute the program and extract all the instruction it goes through. This is done by executing the program step by step and in a step :
-  Collect the successive adresses taken by the RIP register (instruction pointer register)
  
- Disassemble the first instruction in memory at this adress

We have a list of adresses and instruction, then we need to detect conditional jumps, to do so, we search for a "cmp" condition, followed by a jump instruction (je, jz, jg, ...)

## Dependencies

- **capstone** : Used to disassemble the executable.

## Note

First versions will be oriented on functionality, and may not be stable or beautiful, but some cleaning will arrive, I promise.

## TODO

Pretty much everything except the step by step thing

## Journal de bord :

--> 11/04/2025 : program trace of programs done.

--> 18/04/2025 : refactoring code (now beautiful)