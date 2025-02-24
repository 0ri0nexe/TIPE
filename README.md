# TIPE

## Introcution

A work for my project on processor's branch prediction algorithm.

The use of this repo might change in the future, for now its goal is to extract conditionnal jumps taken by a program at execution in order to get real numbers from actual programs to then benchmark different branch prediction technics.

## Method

To do so we need to :

- execute the program and extract all the instruction it goes through. This is done by executing the program step by step like we would do with a debugger and collecting the successive adresses the RIP register takes.
  
- Detect conditional jumps adresses. We need to find paterns in the assembly which are related to conditionnal jumps. It will be hard to be hexaustive, but the goal is to miss as few conditions as possible.

## Dependencies

- **capstone** : Used to disassemble the executable.

## Note

First versions will be oriented on functionality, and may not be stable or beautiful, but some cleaning will arrive, I promise.

## TODO

Pretty much everything except the step by step thing