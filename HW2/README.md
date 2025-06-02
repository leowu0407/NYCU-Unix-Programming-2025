# UP25 HW2
Due Date: 2025-06-02
[TOC]

## Simple Instruction Level Debugger

In this homework, you have to implement a simple instruction-level debugger that allows a user to debug a program interactively at the assembly instruction level. You should implement the debugger by using the `ptrace` interface in C, C++, 🦀 Rust, or ⚡ Zig. The commands you have to implement are detailed in the [Commands Requirements](#Commands-Requirements).

-  Your debugger must support **x86-64** binaries, including both static and dynamically linked executables, as well as **PIE** (Position-Independent Executable) enabled binaries.
-  You don't need to handle the program that might use `fork`, `vfork`, `clone`, `clone3`, `execve`, `execveat` syscalls.
- We use the [sample program](https://up.zoolab.org/unixprog/hw02/hw2_testing_program.zip) to demonstrate how to use the debugger.

### Usage

- You can load a program after/when the debugger starts. See the [load program](#Load-Program) section for the details.

- You should print "`(sdb) `" as the prompt in every line, no matter whether you have loaded the program.

```bash
# Launch the debugger directly
$ ./sdb
# Launch the debugger with a program
$ ./sdb [program]
...
```

## Commands Requirements

:::info
We will not test any error handling not mentioned in this spec. You can determine how to handle the other errors by yourself.
:::

### Load Program

- Command: `load [path to a program]`

- Load a program after the debugger starts.
    - You should output `** please load a program first.` if you input any other commands before loading a program.

- When the program is loaded:
    - The debugger should print the **name of the executable and the entry point address**.
    - Before waiting for the user’s input, the debugger should **stop at the entry point of the target binary** and **disassemble 5 instructions** starting from the current program counter (rip).

- Sample output of `./sdb`
```
(sdb) info reg
** please load a program first.
(sdb) load ./hello
** program './hello' loaded. entry point: 0x401620.
      401620: f3 0f 1e fa                      endbr64
      401624: 31 ed                            xor       ebp, ebp
      401626: 49 89 d1                         mov       r9, rdx
      401629: 5e                               pop       rsi
      40162a: 48 89 e2                         mov       rdx, rsp
```
- Sample output of `./sdb ./hello`
```
** program './hello' loaded. entry point: 0x401620.
      401620: f3 0f 1e fa                      endbr64
      401624: 31 ed                            xor       ebp, ebp
      401626: 49 89 d1                         mov       r9, rdx
      401629: 5e                               pop       rsi
      40162a: 48 89 e2                         mov       rdx, rsp
(sdb)
```

- Sample output of `./sdb ./hola`
```
** program './hola' loaded. entry point: 0x599402b70080.
      599402b70080: f3 0f 1e fa                      endbr64
      599402b70084: 31 ed                            xor       ebp, ebp
      599402b70086: 49 89 d1                         mov       r9, rdx
      599402b70089: 5e                               pop       rsi
      599402b7008a: 48 89 e2                         mov       rdx, rsp
(sdb)
```

:::info
**Note:**
- For dynamic linked ELF (e.g. `hola`), you need to stop on the entry point of the **target binary**, not the dynamic linker's entry point. (You can set a breakpoint at the entrypoint after first stop, and continue the execution.)
- Due to `hola` also has PIE enabled, the address will differ each time you run the program, but the instructions you got should remain the same.
- You can verify the entry point offset by running:
      `readelf -h ./hola | grep Entry`
    - If `readelf` is not available, install the `binutils` package for your Linux distribution first.
    - For your convenience, the offset of the entry point of `hola` is `0x1080`
:::

### Disassemble

When returning from execution, the debugger should disassemble 5 instructions starting from the current program counter (instruction pointer). The address of the 5 instructions should be within the range of the executable region. We do not care about the format, but in each line, there should be:

1. address, e.g. `401005`
2. raw instructions in a grouping of 1 byte, e.g., `48 89 e5`
3. mnemonic, e.g., `mov`
4. operands of the instruction, e.g., `edx, 0xe`

And make sure that
- The output is aligned with the columns.
- If the disassembled instructions are less than 5 because current program counter is near the boundary of executable region or not in the executable region, output `** the address is out of the range of the executable region.`

Sample output (assume only addresses from `0x401000` to `0x402000` are executable):
```
(sdb) si
      401026: e8 10 00 00 00                    call      0x40103b
      40102b: b8 01 00 00 00                    mov       eax, 1
      401030: 0f 05                             syscall
      401032: c3                                ret
      401033: b8 00 00 00 00                    mov       eax, 0
(sdb) ...
...
(sdb) si
      401ffe: 0f 05                             syscall
** the address is out of the range of the executable region.
```

:::info
**Note:**
- You should only disassemble the program when the program is loaded or when using `si`, `cont` and `syscall` commands.
- If the `break` command **sets a breakpoint** using patched instructions like `0xcc` (int3), it should not appear in the output.
- If the `patch` command is used in the executable region, the disassembled code should be the patched value, see the [patch](#Patch-Memory) section for examples.
:::

:::info
**Hint:** You can link against the `capstone` library for disassembling.

Note that the disassembly output of capstone v5 and v4 might be different, just make sure they have the same meaning. (e.g. `mov rcx, 0xffffffffffffffb8` vs `mov rcx, -0x48`).
:::

### Step Instruction

- Command: `si`

- Execute a single instruction.
    - If the program hits a breakpoint, output `** hit a breakpoint at [addr].`
    - If the program terminates, output `** the target program terminated.`

- Sample output (assume only addresses from `0x401000` to `0x402000` are executable):
```
(sdb) break 401629
** set a breakpoint at 0x401629.
(sdb) si
** hit a breakpoint at 0x401629.
      401629: 5e                               pop       rsi
      40162a: 48 89 e2                         mov       rdx, rsp
      40162d: 48 83 e4 f0                      and       rsp, 0xfffffffffffffff0
      401631: 50                               push      rax
      401632: 54                               push      rsp
(sdb) si
      40162a: 48 89 e2                         mov       rdx, rsp
      40162d: 48 83 e4 f0                      and       rsp, 0xfffffffffffffff0
      401631: 50                               push      rax
      401632: 54                               push      rsp
      401633: 45 31 c0                         xor       r8d, r8d
(sdb) ...
...
(sdb) si
      401ffe: 0f 05                             syscall
** the address is out of the range of the executable region.
(sdb) si
** the target program terminated.
```

### Continue

- Command: `cont`

- Continue the execution of the target program. The program should keep running until it terminates or hits a breakpoint.
    - If the program hits a breakpoint, output `** hit a breakpoint at [addr].`
    - If the program terminates, output `** the target program terminated.`

- Sample output:
```
(sdb) break 0x40100d
** set a breakpoint at 0x40100d.
(sdb) cont
** hit a breakpoint at 0x40100d.
      40100d: 48 8d 05 ec 0f 00 00              lea       rax, [rip + 0xfec]
      401014: 48 89 c6                          mov       rsi, rax
      401017: bf 01 00 00 00                    mov       edi, 1
      40101c: e8 0a 00 00 00                    call      0x40102b
      401021: bf 00 00 00 00                    mov       edi, 0
(sdb) cont
hello world!
** the target program terminated.
```

:::info
**Note:** If your implementation of `cont` requires the use of `PTRACE_SINGLE_STEP` and `int3`, you can only utilize a maximum of **two ptrace (PTRACE_SINGLE_STEP) and two int3** in the implementation of `cont`, or you will receive 0 points.
:::

### Info Registers

- Command: `info reg`

- Show all the registers and their corresponding values in hex.
    - You should output 3 registers in each line.
    - Values should be printed in 64-bit hex format.
    - **Note:** The output of `$rbp` and `$rsp` can be different.

- Sample output:
```
(sdb) info reg
$rax 0x0000000000000001    $rbx 0x0000000000000000    $rcx 0x0000000000000000
$rdx 0x000000000000000e    $rsi 0x0000000000402000    $rdi 0x0000000000000001
$rbp 0x00007ffdc479ab68    $rsp 0x00007ffdc479ab60    $r8  0x0000000000000000
$r9  0x0000000000000000    $r10 0x0000000000000000    $r11 0x0000000000000000
$r12 0x0000000000000000    $r13 0x0000000000000000    $r14 0x0000000000000000
$r15 0x0000000000000000    $rip 0x0000000000401030    $eflags 0x0000000000000202
```

### Breakpoint

#### Break at address

- Command: `break [hex address]`

- Set up a break point at the specified address. The target program should stop before the instruction at the specified address is executed. If the user resumes the program with `si` , `cont` or `syscall`, the program should not stop at the same breakpoint twice.
    - On success, output `** set a breakpoint at [hex address].`
    - On failure, output `** the target address is not valid.`
- Your debugger should accept both formats of `[hex address]`, with or without the `0x` prefix.
    - Same as other requirement.


- Sample output:
```
(sdb) break 0x401005
** set a breakpoint at 0x401005.
(sdb) break 40100d
** set a breakpoint at 0x40100d.
(sdb) si
** hit a breakpoint at 0x401005.
      401005: 48 89 e5                          mov       rbp, rsp
      401008: ba 0e 00 00 00                    mov       edx, 0xe
      40100d: 48 8d 05 ec 0f 00 00              lea       rax, [rip + 0xfec]
      401014: 48 89 c6                          mov       rsi, rax
      401017: bf 01 00 00 00                    mov       edi, 1
(sdb) si
      401008: ba 0e 00 00 00                    mov       edx, 0xe
      40100d: 48 8d 05 ec 0f 00 00              lea       rax, [rip + 0xfec]
      401014: 48 89 c6                          mov       rsi, rax
      401017: bf 01 00 00 00                    mov       edi, 1
      40101c: e8 0a 00 00 00                    call      0x40102b
```
:::info
**Note:** If you set a breakpoint at the address that current `$rip` points to, you should just go on next address after typing `si`, `cont` or `syscall` and **do not** output `** hit a breakpoint at [hex address].`
This means that the program will not stop at the address that current `$rip` points to if you set a breakpoint on it.
:::

#### Break at **Offset of Target Binary**

- Command: `breakrva [hex offset]`

- Sets a breakpoint relative to the **base address** of the target binary by the given offset, which is useful for the PIE-enabled binary.
    - On success, output `** set a breakpoint at [hex address].`
        - Note: `[hex address]` should be `base_address + offset`
    - On failure, output `** the target address is not valid.`

```
** program './hola' loaded. entry point: 0x60e3bc932080.
      60e3bc932080: f3 0f 1e fa                      endbr64
      60e3bc932084: 31 ed                            xor       ebp, ebp
      60e3bc932086: 49 89 d1                         mov       r9, rdx
      60e3bc932089: 5e                               pop       rsi
      60e3bc93208a: 48 89 e2                         mov       rdx, rsp
(sdb) breakrva 11C3
** set a breakpoint at 0x60e3bc9321c3.
(sdb) cont
** hit a breakpoint at 0x60e3bc9321c3.
      60e3bc9321c3: f3 0f 1e fa                      endbr64
      60e3bc9321c7: 55                               push      rbp
      60e3bc9321c8: 48 89 e5                         mov       rbp, rsp
      60e3bc9321cb: 48 83 ec 20                      sub       rsp, 0x20
      60e3bc9321cf: 64 48 8b 04 25 28 00 00 00       mov       rax, qword ptr fs:[0x28]
(sdb)
```

### Info Breakpoints

- Command: `info break`

- List breakpoints with index numbers (for deletion) and addresses.
    - The index of the breakpoints starts from `0`.
    - If no breakpoints, output `** no breakpoints.`
    - If a breakpoint is deleted, the index of the other breakpoints should remain the same.
    - **Note:** Also, if you add a new breakpoint, continue the indexing instead of filling the deleted index.

- Sample output:

```
(sdb) info break
** no breakpoints.
(sdb) break 0x4000ba
** set a breakpoint at 0x4000ba.
(sdb) break 0x4000bf
** set a breakpoint at 0x4000bf.
(sdb) info break
Num     Address
0       0x4000ba
1       0x4000bf
(sdb) delete 0
** delete breakpoint 0.
(sdb) info break
Num     Address
1       0x4000bf
(sdb) break 0x4000ba
** set a breakpoint at 0x4000ba.
(sdb) info break
Num     Address
1       0x4000bf
2       0x4000ba
```

### Delete Breakpoints

- Command: `delete [id]`

- Remove a break point with the specified id. The id is corresponding to the index number in [Info Breakpoints](#Info-Breakpoints).
    - On success, output `** delete breakpoint [id].`
    - If the breakpoint id does not exist, output `** breakpoint [id] does not exist.`

- Sample output:
```
(sdb) break 0x4000ba
** set a breakpoint at 0x4000ba.
(sdb) info break
Num     Address
0       0x4000ba
(sdb) delete 0
** delete breakpoint 0.
(sdb) delete 0
** breakpoint 0 does not exist.
```

### Patch Memory

- Command: `patch [hex address] [hex string]`

- Patch memory starts at the `address` with the `[hex string]`. The maximum of the `strlen([hex string])` is `2048`, and you don't need to handle the case that `strlen([hex string]) % 2 != 0` (which means that we will not given input like `a`, `aab` or `aabbc`)
    - If the patch address and the size of the hex string is valid, output `** patch memory at [hex address].`
    - If `[hex address]` is not a valid address or `[hex address] + sizeof([hex string])` is not a valid address, output `** the target address is not valid.`.

:::info
**Note:**
-  If you patch on an instruction that has been set as a breakpoint, the breakpoint should still exist, but the original instruction should be patched.
:::
    
- Sample output:
```
(sdb) si
      401017: bf 01 00 00 00                    mov       edi, 1
      40101c: e8 0a 00 00 00                    call      0x40102b
      401021: bf 00 00 00 00                    mov       edi, 0
      401026: e8 10 00 00 00                    call      0x40103b
      40102b: b8 01 00 00 00                    mov       eax, 1
(sdb) patch 0x40101c 9000
** patch memory at 0x40101c.
(sdb) si
      40101c: 90                                nop
      40101d: 00 00                             add       byte ptr [rax], al
      40101f: 00 00                             add       byte ptr [rax], al
      401021: bf 00 00 00 00                    mov       edi, 0
      401026: e8 10 00 00 00                    call      0x40103b
(sdb) 
```

### System Call

- Command: `syscall`

- The program execution should break at every system call instruction **unless it hits a breakpoint**.
    - If it hits a breakpoint, output `** hit a breakpoint at [hex address].`
    - If it enters a syscall, output `** enter a syscall([nr]) at [hex address].`
    - If it leaves a syscall, output `** leave a syscall([nr]) = [ret] at [hex address].`

:::info
**Note:** You can ignore the cases where a breakpoint is set on a syscall instruction.
:::

- Sample output:
```
(sdb) syscall
** hit a breakpoint at 0x401008.
      401008: ba 0e 00 00 00                  	mov       edx, 0xe
      40100d: 48 8d 05 ec 0f 00 00            	lea       rax, [rip + 0xfec]
      401014: 48 89 c6                        	mov       rsi, rax
      401017: bf 01 00 00 00                  	mov       edi, 1
      40101c: e8 0a 00 00 00                  	call      0x40102b
(sdb) syscall
** enter a syscall(1) at 0x401030.
      401030: 0f 05                           	syscall   
      401032: c3                              	ret       
      401033: b8 00 00 00 00                  	mov       eax, 0
      401038: 0f 05                           	syscall   
      40103a: c3                              	ret       
(sdb) syscall
hello world!
** leave a syscall(1) = 14 at 0x401030.
      401030: 0f 05                           	syscall   
      401032: c3                              	ret       
      401033: b8 00 00 00 00                  	mov       eax, 0
      401038: 0f 05                           	syscall   
      40103a: c3                              	ret 
```

## Examples

We use the [sample program](https://up.zoolab.org/unixprog/hw02/hw2_testing_program.zip) to demonstrate the following examples.

### Example 1-1 (5%)

- Requirements: `load` `cont` `si` `disassemble`
- Launch debugger: `./sdb`
- Input:
```
si
load ./hello
si
si
cont
```
- Sample:
```
(sdb) si
** please load a program first.
(sdb) load ./hello
** program './hello' loaded. entry point: 0x401620.
      401620: f3 0f 1e fa                      endbr64
      401624: 31 ed                            xor       ebp, ebp
      401626: 49 89 d1                         mov       r9, rdx
      401629: 5e                               pop       rsi
      40162a: 48 89 e2                         mov       rdx, rsp
(sdb) si
      401624: 31 ed                            xor       ebp, ebp
      401626: 49 89 d1                         mov       r9, rdx
      401629: 5e                               pop       rsi
      40162a: 48 89 e2                         mov       rdx, rsp
      40162d: 48 83 e4 f0                      and       rsp, 0xfffffffffffffff0
(sdb) si
      401626: 49 89 d1                         mov       r9, rdx
      401629: 5e                               pop       rsi
      40162a: 48 89 e2                         mov       rdx, rsp
      40162d: 48 83 e4 f0                      and       rsp, 0xfffffffffffffff0
      401631: 50                               push      rax
(sdb) cont
hello world!
** the target program terminated.
```

### Example 1-2 (5%)

- Requirements: `load` `cont` `si` `disassemble`
- Launch debugger: `./sdb ./hola`
- Input:
```
si
si
cont
```
- Sample:
```
** program './hola' loaded. entry point: 0x5a50f11f3080.
      5a50f11f3080: f3 0f 1e fa                      endbr64
      5a50f11f3084: 31 ed                            xor       ebp, ebp
      5a50f11f3086: 49 89 d1                         mov       r9, rdx
      5a50f11f3089: 5e                               pop       rsi
      5a50f11f308a: 48 89 e2                         mov       rdx, rsp
(sdb) si
      5a50f11f3084: 31 ed                            xor       ebp, ebp
      5a50f11f3086: 49 89 d1                         mov       r9, rdx
      5a50f11f3089: 5e                               pop       rsi
      5a50f11f308a: 48 89 e2                         mov       rdx, rsp
      5a50f11f308d: 48 83 e4 f0                      and       rsp, 0xfffffffffffffff0
(sdb) si
      5a50f11f3086: 49 89 d1                         mov       r9, rdx
      5a50f11f3089: 5e                               pop       rsi
      5a50f11f308a: 48 89 e2                         mov       rdx, rsp
      5a50f11f308d: 48 83 e4 f0                      and       rsp, 0xfffffffffffffff0
      5a50f11f3091: 50                               push      rax
(sdb) cont
hola mundo!
** the target program terminated.
```

:::info
**Note:**
- The output of the addresses should be different, just make sure the offset of the entrypoint and the instructions are the same.
- We used [`patchelf`](https://github.com/NixOS/patchelf) to link `hola` with `libc.so.6` and `ld-linux-x86-64.so.2` located in the same directory. Therefore, you need to `cd` into the directory containing `hola` to run the program properly.
    - For example: `(cd ./hw2_testing_program; ../sdb ./hola)`
:::

### Example 2 (10%)
- Requirements: `break` `breakrva` `info break` `info reg`
- Launch debugger: `./sdb ./hello`
- Input:
```
break 0x401626
breakrva 17e6
info break
si
si
cont
info reg
cont
```
- Sample:
```
** program './hello' loaded. entry point: 0x401620.
      401620: f3 0f 1e fa                      endbr64
      401624: 31 ed                            xor       ebp, ebp
      401626: 49 89 d1                         mov       r9, rdx
      401629: 5e                               pop       rsi
      40162a: 48 89 e2                         mov       rdx, rsp
(sdb) break 0x401626
** set a breakpoint at 0x401626.
(sdb) breakrva 17e6
** set a breakpoint at 0x4017e6.
(sdb) info break
Num     Address
0       0x401626
1       0x4017e6
(sdb) si
      401624: 31 ed                            xor       ebp, ebp
      401626: 49 89 d1                         mov       r9, rdx
      401629: 5e                               pop       rsi
      40162a: 48 89 e2                         mov       rdx, rsp
      40162d: 48 83 e4 f0                      and       rsp, 0xfffffffffffffff0
(sdb) si
** hit a breakpoint at 0x401626.
      401626: 49 89 d1                         mov       r9, rdx
      401629: 5e                               pop       rsi
      40162a: 48 89 e2                         mov       rdx, rsp
      40162d: 48 83 e4 f0                      and       rsp, 0xfffffffffffffff0
      401631: 50                               push      rax
(sdb) cont
** hit a breakpoint at 0x4017e6.
      4017e6: e8 5a ff ff ff                   call      0x401745
      4017eb: bf 00 00 00 00                   mov       edi, 0
      4017f0: e8 84 ff ff ff                   call      0x401779
      4017f5: b8 00 00 00 00                   mov       eax, 0
      4017fa: 48 8b 55 f8                      mov       rdx, qword ptr [rbp - 8]
(sdb) info reg
$rax 0x00007ffce35418fa    $rbx 0x00007ffce3541b08    $rcx 0x0000000000000006
$rdx 0x000000000000000d    $rsi 0x00007ffce35418fa    $rdi 0x0000000000000001
$rbp 0x00007ffce3541910    $rsp 0x00007ffce35418f0    $r8  0x00000000004c7d70
$r9  0x0000100000000000    $r10 0x0000000000000080    $r11 0x0000000000000206
$r12 0x0000000000000001    $r13 0x00007ffce3541af8    $r14 0x00000000004c17d0
$r15 0x0000000000000001    $rip 0x00000000004017e6    $eflags 0x0000000000000246
(sdb) cont
hello world!
** the target program terminated.
```
:::info
**Note:** Make sure that `$rbp - $rsp` equals to `0x20`.
:::


### Example 3 (10%)
- Requirements: `delete` `patch`
- Launch debugger: `./sdb ./rana`
- Input:
```
break 401798
cont
cont
patch 40179e 7f
info break
delete 0
patch deadbeef 1337
break deadbeef
breakrva deadbeef
cont
```

- Sample:
```
** program './rana' loaded. entry point: 0x401650.
      401650: f3 0f 1e fa                      endbr64
      401654: 31 ed                            xor       ebp, ebp
      401656: 49 89 d1                         mov       r9, rdx
      401659: 5e                               pop       rsi
      40165a: 48 89 e2                         mov       rdx, rsp
(sdb) break 401798
** set a breakpoint at 0x401798.
(sdb) cont
** hit a breakpoint at 0x401798.
      401798: 8b 45 f8                         mov       eax, dword ptr [rbp - 8]
      40179b: 3b 45 fc                         cmp       eax, dword ptr [rbp - 4]
      40179e: 7e 11                            jle       0x4017b1
      4017a0: 48 8d 05 5d 68 09 00             lea       rax, [rip + 0x9685d]
      4017a7: 48 89 c7                         mov       rdi, rax
(sdb) cont
matcha parfait
** hit a breakpoint at 0x401798.
      401798: 8b 45 f8                         mov       eax, dword ptr [rbp - 8]
      40179b: 3b 45 fc                         cmp       eax, dword ptr [rbp - 4]
      40179e: 7e 11                            jle       0x4017b1
      4017a0: 48 8d 05 5d 68 09 00             lea       rax, [rip + 0x9685d]
      4017a7: 48 89 c7                         mov       rdi, rax
(sdb) patch 40179e 7f
** patch memory at 0x40179e.
(sdb) info break
Num     Address
0       0x401798
(sdb) delete 0
** delete breakpoint 0.
(sdb) patch deadbeef 1337
** the target address is not valid.
(sdb) break deadbeef
** the target address is not valid.
(sdb) breakrva deadbeef
** the target address is not valid.
(sdb) cont
live!
live!
** the target program terminated.
```

### Example 4 (10%)
- Requirements: `syscall`
- Launch debugger: `./sdb ./hello`
- Input:
```
break 0x40179F
break 4017B4
cont
syscall
syscall
syscall
syscall
syscall
```
- Sample:
```
** program './hello' loaded. entry point: 0x401620.
      401620: f3 0f 1e fa                      endbr64
      401624: 31 ed                            xor       ebp, ebp
      401626: 49 89 d1                         mov       r9, rdx
      401629: 5e                               pop       rsi
      40162a: 48 89 e2                         mov       rdx, rsp
(sdb) break 0x40179F
** set a breakpoint at 0x40179f.
(sdb) break 4017B4
** set a breakpoint at 0x4017b4.
(sdb) cont
** hit a breakpoint at 0x40179f.
      40179f: f3 0f 1e fa                      endbr64
      4017a3: 55                               push      rbp
      4017a4: 48 89 e5                         mov       rbp, rsp
      4017a7: 48 83 ec 20                      sub       rsp, 0x20
      4017ab: 64 48 8b 04 25 28 00 00 00       mov       rax, qword ptr fs:[0x28]
(sdb) syscall
** hit a breakpoint at 0x4017b4.
      4017b4: 48 89 45 f8                      mov       qword ptr [rbp - 8], rax
      4017b8: 31 c0                            xor       eax, eax
      4017ba: 48 b8 68 65 6c 6c 6f 20 77 6f    movabs    rax, 0x6f77206f6c6c6568
      4017c4: 48 89 45 ea                      mov       qword ptr [rbp - 0x16], rax
      4017c8: c7 45 f2 72 6c 64 21             mov       dword ptr [rbp - 0xe], 0x21646c72
(sdb) syscall
** enter a syscall(1) at 0x447e4b.
      447e4b: 0f 05                            syscall
      447e4d: 48 3d 01 f0 ff ff                cmp       rax, -0xfff
      447e53: 73 01                            jae       0x447e56
      447e55: c3                               ret
      447e56: 48 c7 c1 b8 ff ff ff             mov       rcx, 0xffffffffffffffb8
(sdb) syscall
hello world!
** leave a syscall(1) = 13 at 0x447e4b.
      447e4b: 0f 05                            syscall
      447e4d: 48 3d 01 f0 ff ff                cmp       rax, -0xfff
      447e53: 73 01                            jae       0x447e56
      447e55: c3                               ret
      447e56: 48 c7 c1 b8 ff ff ff             mov       rcx, 0xffffffffffffffb8
(sdb) syscall
** enter a syscall(60) at 0x447e4b.
      447e4b: 0f 05                            syscall
      447e4d: 48 3d 01 f0 ff ff                cmp       rax, -0xfff
      447e53: 73 01                            jae       0x447e56
      447e55: c3                               ret
      447e56: 48 c7 c1 b8 ff ff ff             mov       rcx, 0xffffffffffffffb8
(sdb) syscall
** the target program terminated.
```

:::info
The disassembly output of capstone v5 and v4 might be different, just make sure they have the same meaning. (e.g. `mov rcx, 0xffffffffffffffb8` vs `mov rcx, -0x48`).
:::

### Extra Example (0%)
- Launch debugger: `./sdb ./anon`
- Input:
```
break 401828
cont
si
break 0x700000000ffa
cont
si
si
si
cont
```
- Sample:
```
** program './anon' loaded. entry point: 0x401650.
      401650: f3 0f 1e fa                      endbr64
      401654: 31 ed                            xor       ebp, ebp
      401656: 49 89 d1                         mov       r9, rdx
      401659: 5e                               pop       rsi
      40165a: 48 89 e2                         mov       rdx, rsp
(sdb) break 401828
** set a breakpoint at 0x401828.
(sdb) cont
** hit a breakpoint at 0x401828.
      401828: ff d2                            call      rdx
      40182a: 48 8d 05 cf 38 0c 00             lea       rax, [rip + 0xc38cf]
      401831: 48 89 c7                         mov       rdi, rax
      401834: e8 37 ae 00 00                   call      0x40c670
      401839: b8 00 00 00 00                   mov       eax, 0
(sdb) si
      700000000000: 90                               nop
      700000000001: 90                               nop
      700000000002: 90                               nop
      700000000003: 90                               nop
      700000000004: 90                               nop
(sdb) break 0x700000000ffa
** set a breakpoint at 0x700000000ffa.
(sdb) cont
** hit a breakpoint at 0x700000000ffa.
      700000000ffa: 90                               nop
      700000000ffb: 90                               nop
      700000000ffc: 90                               nop
      700000000ffd: 90                               nop
      700000000ffe: 90                               nop
(sdb) si
      700000000ffb: 90                               nop
      700000000ffc: 90                               nop
      700000000ffd: 90                               nop
      700000000ffe: 90                               nop
      700000000fff: c3                               ret
(sdb) si
      700000000ffc: 90                               nop
      700000000ffd: 90                               nop
      700000000ffe: 90                               nop
      700000000fff: c3                               ret
** the address is out of the range of the executable region.
(sdb) si
      700000000ffd: 90                               nop
      700000000ffe: 90                               nop
      700000000fff: c3                               ret
** the address is out of the range of the executable region.
(sdb) cont
Welcome to ANON TOKYO!

** the target program terminated.
```
:::info
The example is just for you to test disassembling instructions when current program counter is near the boundary of executable region.
:::

## Hints

- You can use `/proc/[pid]/auxv`, `/proc/[pid]/maps`, and `/proc/[pid]/mem` to get some useful information of the running process
    - http://man.he.net/man5/procfs
- ptrace: http://man.he.net/man2/ptrace
- How Linux kernel load your ELF: https://elixir.bootlin.com/linux/v6.15-rc5/source/fs/binfmt_elf.c

## Homework Submission

- Due time: 2025-06-02 15:30
- Filename: `{studentID}_hw2.tar` or `{studentID}_hw2.tgz`
- Format:

```
+---{studentID}_hw2
|    Makefile
|    [sdb.c/sdb.cpp]
|    [Cargo.toml]
|    [build.zig]
|    [flake.nix]
|    ...
```

## Grading

- [40%] Your program has the correct output for all  [example test cases](#Examples).

- [60%] We use `N` hidden test cases to evaluate your implementation. You get `60/N` points for each correct test case.

:::danger
Plagiarism is not allowed. Any student who is caught plagiarizing will receive a zero. 🫵
:::

## Demo
- Date: 2025-06-02



# UP25 HW2 Hidden case
[TOC]

## Setup

Download link: [hw2_demo_program.zip](https://up.zoolab.org/unixprog/hw02/hw2_demo_program.zip)

:::info
Tips:

You can `ln -s /path/to/your/sdb sdb` inside your `hw2_demo_program`.

e.g.:

```shell
$ curl -sSfLO https://up.zoolab.org/unixprog/hw02/hw2_demo_program.zip
$ unzip hw2_demo_program.zip
Archive:  hw2_demo_program.zip
   creating: hw2_demo_program/
  inflating: hw2_demo_program/anon
  inflating: hw2_demo_program/hello
  inflating: hw2_demo_program/hola
  inflating: hw2_demo_program/ld-linux-x86-64.so.2
  inflating: hw2_demo_program/libc.so.6
  inflating: hw2_demo_program/mortis
  inflating: hw2_demo_program/rana
  inflating: hw2_demo_program/soyorin
$ ln -s ../../zig-out/bin/sdb hw2_demo_program/sdb
$ ls -al hw2_demo_program
total 5.6M
-rwxr-xr-x 1 501 dialout 801K Jun  1 10:45 anon
-rwxr-xr-x 1 501 dialout 801K Jun  1 10:45 hello
-rwxr-xr-x 1 501 dialout  21K Jun  1 10:45 hola
-rwxr-xr-x 1 501 dialout 236K Jun  1 10:45 ld-linux-x86-64.so.2
-rwxr-xr-x 1 501 dialout 2.2M Jun  1 10:45 libc.so.6
-rwxr-xr-x 1 501 dialout  23K Jun  1 10:45 mortis
-rwxr-xr-x 1 501 dialout 801K Jun  1 10:45 rana
lrwxr-xr-x 1 501 dialout   21 Jun  1 10:51 sdb -> ../../zig-out/bin/sdb
-rwxr-xr-x 1 501 dialout 845K Jun  1 10:45 soyorin
```
:::

## Hidden Case 1 (15%)

- input: `./sdb ./mortis`
```
info reg
break 401210
break 401214
cont
si
cont
si
patch 0x4011d8 580f05
patch 0x4011d4 31ff6a3c
si
cont
```

- output

```
** program './mortis' loaded. entry point: 0x401070.
      401070: f3 0f 1e fa                      endbr64
      401074: 31 ed                            xor       ebp, ebp
      401076: 49 89 d1                         mov       r9, rdx
      401079: 5e                               pop       rsi
      40107a: 48 89 e2                         mov       rdx, rsp
(sdb) info reg
$rax 0x000000000000001c    $rbx 0x0000000000000000    $rcx 0x00007ffed845da18
$rdx 0x0000788e0e8ee040    $rsi 0x0000788e0e923888    $rdi 0x0000788e0e9232e0
$rbp 0x0000000000000000    $rsp 0x00007ffed845da00    $r8  0x0000000000000840
$r9  0x0000080000000000    $r10 0x0000788e0e8e8860    $r11 0x0000788e0e8ffd70
$r12 0x0000000000401070    $r13 0x00007ffed845da00    $r14 0x0000000000000000
$r15 0x0000000000000000    $rip 0x0000000000401070    $eflags 0x0000000000000202
(sdb) break 401210
** set a breakpoint at 0x401210.
(sdb) break 401214
** set a breakpoint at 0x401214.
(sdb) cont
** hit a breakpoint at 0x401210.
      401210: 83 7d dc 04                      cmp       dword ptr [rbp - 0x24], 4
      401214: 7e be                            jle       0x4011d4
      401216: bf 00 00 00 00                   mov       edi, 0
      40121b: e8 6a ff ff ff                   call      0x40118a
      401220: b8 00 00 00 00                   mov       eax, 0
(sdb) si
** hit a breakpoint at 0x401214.
      401214: 7e be                            jle       0x4011d4
      401216: bf 00 00 00 00                   mov       edi, 0
      40121b: e8 6a ff ff ff                   call      0x40118a
      401220: b8 00 00 00 00                   mov       eax, 0
      401225: 48 8b 55 f8                      mov       rdx, qword ptr [rbp - 8]
(sdb) cont
I like cucumbers
** hit a breakpoint at 0x401210.
      401210: 83 7d dc 04                      cmp       dword ptr [rbp - 0x24], 4
      401214: 7e be                            jle       0x4011d4
      401216: bf 00 00 00 00                   mov       edi, 0
      40121b: e8 6a ff ff ff                   call      0x40118a
      401220: b8 00 00 00 00                   mov       eax, 0
(sdb) si
** hit a breakpoint at 0x401214.
      401214: 7e be                            jle       0x4011d4
      401216: bf 00 00 00 00                   mov       edi, 0
      40121b: e8 6a ff ff ff                   call      0x40118a
      401220: b8 00 00 00 00                   mov       eax, 0
      401225: 48 8b 55 f8                      mov       rdx, qword ptr [rbp - 8]
(sdb) patch 0x4011d8 580f05
** patch memory at 0x4011d8.
(sdb) patch 0x4011d4 31ff6a3c
** patch memory at 0x4011d4.
(sdb) si
      4011d4: 31 ff                            xor       edi, edi
      4011d6: 6a 3c                            push      0x3c
      4011d8: 58                               pop       rax
      4011d9: 0f 05                            syscall
      4011db: 65 20 63 48                      and       byte ptr gs:[rbx + 0x48], ah
(sdb) cont
** the target program terminated.
```
    
:::info
Please ensure that some registers (e.g. `$r13`) other than `$rip`, `$rsp`, and `$eflags` contain non-zero values in the `info reg` output.
:::

## Hidden Case 2 (15%)

- input: `./sdb ./soyorin`
```
info reg
breakrva 8943
breakrva 8947
cont
syscall
syscall
syscall
cont
info break
delete 1
info break
cont
delete 0
info break
cont
```

- output

```
** program './soyorin' loaded. entry point: 0x7c2215c917a0.
      7c2215c917a0: f3 0f 1e fa                      endbr64
      7c2215c917a4: 31 ed                            xor       ebp, ebp
      7c2215c917a6: 49 89 d1                         mov       r9, rdx
      7c2215c917a9: 5e                               pop       rsi
      7c2215c917aa: 48 89 e2                         mov       rdx, rsp
(sdb) info reg
$rax 0x0000000000000000    $rbx 0x0000000000000000    $rcx 0x0000000000000000
$rdx 0x0000000000000000    $rsi 0x0000000000000000    $rdi 0x0000000000000000
$rbp 0x0000000000000000    $rsp 0x00007fff19697340    $r8  0x0000000000000000
$r9  0x0000000000000000    $r10 0x0000000000000000    $r11 0x0000000000000000
$r12 0x0000000000000000    $r13 0x0000000000000000    $r14 0x0000000000000000
$r15 0x0000000000000000    $rip 0x00007c2215c917a0    $eflags 0x0000000000000200
(sdb) breakrva 8943
** set a breakpoint at 0x7c2215c91943.
(sdb) breakrva 8947
** set a breakpoint at 0x7c2215c91947.
(sdb) cont
** hit a breakpoint at 0x7c2215c91943.
      7c2215c91943: 83 7d dc 04                      cmp       dword ptr [rbp - 0x24], 4
      7c2215c91947: 7e be                            jle       0x7c2215c91907
      7c2215c91949: bf 00 00 00 00                   mov       edi, 0
      7c2215c9194e: e8 6a ff ff ff                   call      0x7c2215c918bd
      7c2215c91953: b8 00 00 00 00                   mov       eax, 0
(sdb) syscall
** hit a breakpoint at 0x7c2215c91947.
      7c2215c91947: 7e be                            jle       0x7c2215c91907
      7c2215c91949: bf 00 00 00 00                   mov       edi, 0
      7c2215c9194e: e8 6a ff ff ff                   call      0x7c2215c918bd
      7c2215c91953: b8 00 00 00 00                   mov       eax, 0
      7c2215c91958: 48 8b 55 f8                      mov       rdx, qword ptr [rbp - 8]
(sdb) syscall
** enter a syscall(1) at 0x7c2215cd7f8b.
      7c2215cd7f8b: 0f 05                            syscall
      7c2215cd7f8d: 48 3d 01 f0 ff ff                cmp       rax, -0xfff
      7c2215cd7f93: 73 01                            jae       0x7c2215cd7f96
      7c2215cd7f95: c3                               ret
      7c2215cd7f96: 48 c7 c1 b8 ff ff ff             mov       rcx, 0xffffffffffffffb8
(sdb) syscall
She is my friend
** leave a syscall(1) = 17 at 0x7c2215cd7f8b.
      7c2215cd7f8b: 0f 05                            syscall
      7c2215cd7f8d: 48 3d 01 f0 ff ff                cmp       rax, -0xfff
      7c2215cd7f93: 73 01                            jae       0x7c2215cd7f96
      7c2215cd7f95: c3                               ret
      7c2215cd7f96: 48 c7 c1 b8 ff ff ff             mov       rcx, 0xffffffffffffffb8
(sdb) cont
** hit a breakpoint at 0x7c2215c91943.
      7c2215c91943: 83 7d dc 04                      cmp       dword ptr [rbp - 0x24], 4
      7c2215c91947: 7e be                            jle       0x7c2215c91907
      7c2215c91949: bf 00 00 00 00                   mov       edi, 0
      7c2215c9194e: e8 6a ff ff ff                   call      0x7c2215c918bd
      7c2215c91953: b8 00 00 00 00                   mov       eax, 0
(sdb) info break
Num     Address
0       0x7c2215c91943
1       0x7c2215c91947
(sdb) delete 1
** delete breakpoint 1.
(sdb) info break
Num     Address
0       0x7c2215c91943
(sdb) cont
She is my friend
** hit a breakpoint at 0x7c2215c91943.
      7c2215c91943: 83 7d dc 04                      cmp       dword ptr [rbp - 0x24], 4
      7c2215c91947: 7e be                            jle       0x7c2215c91907
      7c2215c91949: bf 00 00 00 00                   mov       edi, 0
      7c2215c9194e: e8 6a ff ff ff                   call      0x7c2215c918bd
      7c2215c91953: b8 00 00 00 00                   mov       eax, 0
(sdb) delete 0
** delete breakpoint 0.
(sdb) info break
** no breakpoints.
(sdb) cont
She is my friend
She is my friend
She is my friend
** the target program terminated.
```
    
:::info
Please ensure that all registers, except for `$rip`, `$rsp`, and `$eflags`, are zero in the `info reg` output.

In addition, the addresses in the disassembly output may differ because the tracee is a PIE-enabled binary.
:::

## Hidden Case 3 (15%)

- input: `./sdb ./rana`
```
break 40179e
cont
break 4017a0
patch 40179e 7f1148
info break
cont
patch 40179e 7e
delete 0
cont
delete 1
cont
```

- output

```
** program './rana' loaded. entry point: 0x401650.
      401650: f3 0f 1e fa                      endbr64
      401654: 31 ed                            xor       ebp, ebp
      401656: 49 89 d1                         mov       r9, rdx
      401659: 5e                               pop       rsi
      40165a: 48 89 e2                         mov       rdx, rsp
(sdb) break 40179e
** set a breakpoint at 0x40179e.
(sdb) cont
** hit a breakpoint at 0x40179e.
      40179e: 7e 11                            jle       0x4017b1
      4017a0: 48 8d 05 5d 68 09 00             lea       rax, [rip + 0x9685d]
      4017a7: 48 89 c7                         mov       rdi, rax
      4017aa: e8 11 aa 00 00                   call      0x40c1c0
      4017af: eb 0f                            jmp       0x4017c0
(sdb) break 4017a0
** set a breakpoint at 0x4017a0.
(sdb) patch 40179e 7f1148
** patch memory at 0x40179e.
(sdb) info break
Num     Address
0       0x40179e
1       0x4017a0
(sdb) cont
live!
** hit a breakpoint at 0x40179e.
      40179e: 7f 11                            jg        0x4017b1
      4017a0: 48 8d 05 5d 68 09 00             lea       rax, [rip + 0x9685d]
      4017a7: 48 89 c7                         mov       rdi, rax
      4017aa: e8 11 aa 00 00                   call      0x40c1c0
      4017af: eb 0f                            jmp       0x4017c0
(sdb) patch 40179e 7e
** patch memory at 0x40179e.
(sdb) delete 0
** delete breakpoint 0.
(sdb) cont
** hit a breakpoint at 0x4017a0.
      4017a0: 48 8d 05 5d 68 09 00             lea       rax, [rip + 0x9685d]
      4017a7: 48 89 c7                         mov       rdi, rax
      4017aa: e8 11 aa 00 00                   call      0x40c1c0
      4017af: eb 0f                            jmp       0x4017c0
      4017b1: 48 8d 05 5b 68 09 00             lea       rax, [rip + 0x9685b]
(sdb) delete 1
** delete breakpoint 1.
(sdb) cont
matcha parfait
matcha parfait
** the target program terminated.
```

## Hidden Case 4 (15%)

- input: `./sdb ./anon`
```
breakrva 1828
cont
break 700000000000
cont
patch 0x700000000fc9 6844200b018134240101010148b875616e67204c4f565048b850726f662e206368504889e66a015f6a135a6a01580f0531ff6a3c58
syscall
syscall
si
patch 0x700000000ffe 0f05
break 700000000ffd
cont
delete 2
cont
```

- output

```
** program './anon' loaded. entry point: 0x401650.
      401650: f3 0f 1e fa                      endbr64
      401654: 31 ed                            xor       ebp, ebp
      401656: 49 89 d1                         mov       r9, rdx
      401659: 5e                               pop       rsi
      40165a: 48 89 e2                         mov       rdx, rsp
(sdb) breakrva 1828
** set a breakpoint at 0x401828.
(sdb) cont
** hit a breakpoint at 0x401828.
      401828: ff d2                            call      rdx
      40182a: 48 8d 05 cf 38 0c 00             lea       rax, [rip + 0xc38cf]
      401831: 48 89 c7                         mov       rdi, rax
      401834: e8 37 ae 00 00                   call      0x40c670
      401839: b8 00 00 00 00                   mov       eax, 0
(sdb) break 700000000000
** set a breakpoint at 0x700000000000.
(sdb) cont
** hit a breakpoint at 0x700000000000.
      700000000000: 90                               nop
      700000000001: 90                               nop
      700000000002: 90                               nop
      700000000003: 90                               nop
      700000000004: 90                               nop
(sdb) patch 0x700000000fc9 6844200b018134240101010148b875616e67204c4f565048b850726f662e206368504889e66a015f6a135a6a01580f0531ff6a3c58
** patch memory at 0x700000000fc9.
(sdb) syscall
** enter a syscall(1) at 0x700000000ff7.
      700000000ff7: 0f 05                            syscall
      700000000ff9: 31 ff                            xor       edi, edi
      700000000ffb: 6a 3c                            push      0x3c
      700000000ffd: 58                               pop       rax
      700000000ffe: 90                               nop
(sdb) syscall
{some interesting output}
** leave a syscall(1) = 19 at 0x700000000ff7.
      700000000ff7: 0f 05                            syscall
      700000000ff9: 31 ff                            xor       edi, edi
      700000000ffb: 6a 3c                            push      0x3c
      700000000ffd: 58                               pop       rax
      700000000ffe: 90                               nop
(sdb) si
      700000000ffb: 6a 3c                            push      0x3c
      700000000ffd: 58                               pop       rax
      700000000ffe: 90                               nop
      700000000fff: c3                               ret
** the address is out of the range of the executable region.
(sdb) patch 0x700000000ffe 0f05
** patch memory at 0x700000000ffe.
(sdb) break 700000000ffd
** set a breakpoint at 0x700000000ffd.
(sdb) cont
** hit a breakpoint at 0x700000000ffd.
      700000000ffd: 58                               pop       rax
      700000000ffe: 0f 05                            syscall
** the address is out of the range of the executable region.
(sdb) delete 2
** delete breakpoint 2.
(sdb) cont
** the target program terminated.
```
