UP25 Lab03
==========
Date: 2025-03-31

[TOC]

# GOTOKU Challenge

This lab aims to play with `LD_PRELOAD` and GOT table. Your mission is to ask our challenge server to solve the sudoku puzzle, i.e., move from the start position (0, 0) to the empty cells and fill in the correct values.

:::danger
Please read the [instructions](#Lab-Instructions) carefully before you implement this lab. You may implement the codes to solve the challenge on an Apple chip-based machine, but the files you submit to the challenge server must be compiled for x86_64 architecture.
:::

## The Challenge Server

The challenge server can be accessed using the `nc` command:

```
nc up.zoolab.org 58164
```

Upon connecting to the challenge server, you must first solve the Proof-of-Work challenge (ref: [pow-solver](https://md.zoolab.org/s/EHSmQ0szV)). Then, you can follow the instructions to upload your ***solver*** implementation, which must be compiled as a ***shared object*** (`.so`) file. Our challenge server will use `LD_PRELOAD` to load your uploaded solver along with the challenge. Therefore, the behavior of the challenge can be controlled by your solver.

Suppose your solver is named `libsolver.so`. Once your solver has been uploaded to the server, it will run your solver in a clean Linux runtime environment using the following command.

```
LD_PRELOAD=/libsolver.so /gotoku
```

To simplify the uploading process, you can use our provided `pwntools` python script to solve the pow and upload your solver binary executable. The upload script (`submit.py`) is available here ([view](https://up.zoolab.org/code.html?file=unixprog/lab03/submit.py) | [download](https://up.zoolab.org/unixprog/lab03/submit.py)). You may need to place the `solpow.py` file in the same directory and invoke the script by passing the path of your solver as the first parameter to the submission script.

:::warning
Please note that for security considerations, the challenge server is run in a chroot'ed environment without the `/proc` filesystem. For getting the GOT entry addresses, please calculate them based on the fixed offset between the `main` function and the involved GOT entries obtained from the `gotoku` executable.
:::

## Lab Instructions

We provide a number of hints for you to solve the challenge. The directions for this lab are listed below.

1. A shared library `libgotoku.so` is available on the challenge server. You may read `libgotoku.h` ([view](https://up.zoolab.org/code.html?file=unixprog/lab03/libgotoku.h) | [download](https://up.zoolab.org/unixprog/lab03/libgotoku.h)) first to see what functions and features are available in the library. A simplified source code of `libgotoku.so` is also available here - `libgotoku_dummy.c` ([view](https://up.zoolab.org/code.html?file=unixprog/lab03/libgotoku_dummy.c) | [download](https://up.zoolab.org/unixprog/lab03/libgotoku_dummy.c)).

1. Note that we did not provide the compiled shared library file for you. However, you can call the functions in the library by locating the function addresses in the library using the [dlopen(3)](https://man7.org/linux/man-pages/man3/dlopen.3.html) and [dlsym(3)](https://man7.org/linux/man-pages/man3/dlsym.3.html) functions. Note that you *<i style="color:red">cannot call `gop_*` functions directly in your solver when it is running on the remote challenge server</i>*, but it's OK to do that if you solve the challenge in your local machine (for testing purposes). Also, note that the two functions (`dlopen` and `dlsym`) only work for functions exported from a shared object.

1. The source code of the challenge is available here - `gotoku.c` ([view](https://up.zoolab.org/code.html?file=unixprog/lab03/gotoku.c) | [download](https://up.zoolab.org/unixprog/lab03/gotoku.c)). The main program (`gotoku.c`) registers the address of its main function, initializes the library, and loads an existing sudoko challenge from `/gotoku.txt`. It then calls `gop_NNN` functions in a fixed order to perform random movements in the sudoko board. Obviously, the random walk process cannot solve the puzzle.

1. A sample `/gotoku.txt` is as follows. You may load and parse it by yourself or reuse the library functions to load it for you. The content of the file will be different every time you connect to the challenge server.

    ```
    2 0 0 1 4 5 9 7 0
    0 7 0 0 3 0 0 2 0
    0 4 6 2 0 7 8 0 0
    0 2 4 9 0 1 3 0 8
    0 6 0 0 8 0 0 0 0
    0 1 8 7 0 2 4 5 9
    0 0 0 4 0 9 7 8 5
    4 0 0 8 7 0 0 0 0
    8 0 7 0 1 0 6 0 0
    ```

    In the example, the puzzle always has a fixed dimension of `9x9` (width x height), filling with the initial values. You need to solve the puzzle by yourself the then call the correct `gop_*` functions to fill in empty cells with correct values.

1. To solve the puzzle correctly, you should control the main program to call the correct movement and filling functions, e.g., `gop_up`, `gop_down`, `gop_left`, `gop_right` for movements and `gop_fill_[1-9]` for filling in a number.

1. It is intuitively that the preloaded solver may hijack some functions to solve this challenge. For example, you can implement `game_init` function in your solver and let it perform anything before or after you call the actual `game_init` function.

1. Since the `gop_NNN` functions are all implemented in the shared library, it is feasible that you can hijack the function calls from the `main` function to the `gop_NNN` functions by modifying the GOT table of the corresponding functions. For example, making function calls to `gop_1`, `gop_2`, and `gop_3` can be altered and become calling `gop_down`, `gop_fill_1`, and `gop_show`, respectively.

   :::danger
   Note: You are not allowed to hijack `gop_*` functions using `LD_PRELOAD` on the challenge server. Please hijack it using the GOT table. 
   :::

1. Locating the *runtime* address of the GOT table in a running process could be tricky. But since we have provided a special function `game_get_ptr`, you can obtain the real address of the `main` function in runtime. We also provide the binary file of the [`gotoku`](https://up.zoolab.org/unixprog/lab03/gotoku) executable. You should be able to find the relative address of the `main` function and each `GOT` table entry from the binary. The relative addresses can be retrieved by `pwntools` using the script.

   ```python
   from pwn import *
   elf = ELF('./gotoku')
   print("main =", hex(elf.symbols['main']))
   print("{:<12s} {:<10s} {:<10s}".format("Func", "GOT Offset", "Symbol Offset"))
   for s in [ f"gop_{i+1}" for i in range(1200)]:
      if s in elf.got:
         print("{:<12s} {:<10x} {:<10x}".format(s, elf.got[s], elf.symbols[s]))
   ```

   Once you have the addresses, you can ***calculate*** the actual addresses of GOT table entries based on the runtime address of the `main` function. One sample snapshot is shown below. Given that the relative address of the `main` function is `0x1b7a9` and the GOT offset of the `gop_1` function is `0x231b0`. Suppose the real address of the `main` function is at `0x55f6edc857a9`. The actual address of the GOT entry for `gop_1` can be obtained by `0x55f6edc857a9 - 0x1b7a9 + 0x231b0`.

   ```
   main = 0x1b7a9
   Func         GOT Offset Symbol Offset
   gop_1       231b0      19a74
   gop_2       21ea8      17464
   ```

1. If you have pwntools installed, you can use the command `checksec` to inspect the `gotoku` program. The output should be

   ```
   Arch:     amd64-64-little
   RELRO:    Full RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      PIE enabled
   ```
   Note the `Full RELRO` message, which means that the address of movement functions will be resolved upon the execution of the challenge. Therefore, your solver may have to make the region *writable* by using the [mprotect(2)](https://man7.org/linux/man-pages/man2/mprotect.2.html) function before you modify the values in the GOT table. Note that the address passed to the mprotect function may need to be multiples of 4KB (page size).

## Additional Notes for Apple Chip Users

If you do not have a working x86_64 machine, you can still solve this challenge. However, you have to work in a Linux docker to perform cross-compilation. You may consider using the `crossbuild` docker images mentioned in [Lab02 Pre-Lab Announcement](https://md.zoolab.org/yHdtmVBwT02hDTuaUVwzZQ). The quick start command is pasted below for your reference.

```
docker run -it --rm --user "$UID:$GID" -v "`pwd`:/build" -w /build -e PS1="buildenv:\w\$ " chuang/crossbuild /bin/bash --norc
```

To compile your solver implementation for x86_64 machines, and replace the `gcc` (or `g++`) command with `x86_64-linux-gnu-gcc` (or `x86_64-linux-gnu-g++`). Sample commands for installing the packages and compiling `libsolver.c` is given below.

```
x86_64-linux-gnu-gcc -o libsolver.so -shared -fPIC libsolver.c
```
 
## Grading

1. [10 pts] Write a `Makefile` to compile, link, and generate `libgotoku.so` (from `libgotoku_dummy.c`) and `gotoku.local` (from `gotoku.c`). You may need `gops.c` file, which can be downloaded from [here](https://up.zoolab.org/unixprog/lab03/gops.c) ([view](https://up.zoolab.org/code.html?file=unixprog/lab03/gops.c)).

1. [<i style="color:red">10+10 pts</i>] (Part A - 10pts) Implement a solver that can solve the challenge, i.e., walk in the puzzle and fill correct values, in your **local** machine. You can work with the `libgotoku.so` and `gotoku` file generated from the previous grading item.

   You must use the following puzzle to test your solver. Place the content of the puzzle in `/gotoku.txt` and run the testcase:
   ```
    0 0 0 0 8 2 0 0 1
    0 2 0 6 1 0 0 9 8
    1 0 0 0 0 5 0 0 0
    5 0 6 4 9 3 0 0 7
    0 3 7 0 2 8 0 4 6
    8 4 2 1 7 6 0 5 0
    0 0 1 8 0 0 7 6 0
    0 8 0 0 0 0 0 1 3
    0 0 3 2 5 1 0 0 4
   ```

   (Part B - 10pts) Similar to the Part A of this scoring item, but we have to enforce the constraints requested in this lab.
   - You cannot modify `gotoku.c` and `libgotoku_dummy.c` - as those operations are not allowed on the server.
   - Your solver must be implemented as a shared object and preloaded using `LD_PRELOAD` - the definition of *solver* defined in the beginning of this lab.
   - Your solver can only call the `gop_*` functions to walk in the puzzle, or modify the GOT table - the same requirement as running on the server.
   -  You cannot print out the `Bingo` message by yourself - the same requirement as running on the server.

:::warning
The above grading items can be done on your own desktop/laptop. It doesn't matter if you are working on either an Intel or Apple chip-based machine.
:::

3. [10 pts] You can produce an `x86-64` solver shared object and submit it to our challenge server. The shared object should print out a message `UP113_GOT_PUZZLE_CHALLENGE` on the server.
    - This must be implemented in your solver C codes. You have to upload the compiled shared object to the server.

1. [10 pts] Use the pwntool scripts to retrieve the GOT addresses of the `gop_*` functions from our provided `gotoku` executable.
    - This is done in your local desktop / laptop.

1. [20 pts] Your solver can obtain the main function address via the `game_get_ptr` function. Once you get the main function address, print it out in the form of `SOLVER: _main = <the-address-you-obtained>`.
    - This must be implemented in your solver C codes. You have to upload the compiled shared object to the server.

1. [30 pts] Your solver can solve the puzzle on the remote challenge server. A few shell commands will be printed out from the challenge server once you have solved the challenge successfully. Run the shell commands and you should get a `Signature Verified Successfully` message from your console.

   The public key displayed in the shell commands should be
   ```
   -----BEGIN PUBLIC KEY-----
   MCowBQYDK2VwAyEAILamhh4aXszHBI25FFaRDEi2SBohmL2wkXKSHMlX38g=
   -----END PUBLIC KEY-----
   ```

:::warning
You have to ensure your working environment has `openssl` installed.
:::

:::danger
We have an execution time limit for your challenge. You have to solve the challenge within about 90s.
:::