UP25 Lab04
==========
Date: 2025-04-21

[TOC]

# Assembly Language Practice

This lab aims to practice assembly programming. Please extend our `libmini` library introduced in the class to support additional features. The required features are summarized in the [Feature List](#Feature-List) section. All the features must be implemented in x86-64 assembly in yasm syntax.

The base package for assembling, running, and evaluating your implementation can be found from here [chals.tbz](https://up.zoolab.org/unixprog/lab04/chals.tbz).

For easier access, the header files can be found from here: [libmini.h](https://github.com/chunying/up-inclass/blob/master/asm/libmini.h) and [libmini-ext.h](https://github.com/chunying/up-inclass/blob/master/asm/libmini-ext.h). The source codes for the base libraries are also available in the same repo: [libmini64.asm](https://github.com/chunying/up-inclass/blob/master/asm/libmini64.asm), [libmini.c](https://github.com/chunying/up-inclass/blob/master/asm/libmini.c), [start.asm](https://github.com/chunying/up-inclass/blob/master/asm/start.asm).

Some of the features may require making a system call. You may refer to [Linux System Call Table for x86 64](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/) document for how to invoke a system call. 

## Feature List

Your library needs to implement the required functions. The prototypes of the required functions are listed as follows.

- `time_t time(time_t * unused);`

   Return the current timestamp. The parameter is always ignored.
   
- `void srand(unsigned int seed);`

   Please read the description in `rand` function.
   
- `unsigned int grand();`

   Return the seed that was previously set using the `srand` function.

- `int rand(void);`

   Please implement this function using the following algorithm.
   
   ```C
   static unsigned long long seed;

   void srand(unsigned s) {
	 seed = s-1;
   }

   int rand(void) {
	 seed = 6364136223846793005ULL*seed + 1;
	 return seed>>33;
   }
   ```

- Implement the following functions to manipulate the `sigset_t` data structure. 

   ```C
   int sigemptyset(sigset_t *set);
   int sigfillset(sigset_t *set);
   int sigaddset(sigset_t *set, int signum);
   int sigdelset(sigset_t *set, int signum);
   int sigismember(const sigset_t *set, int signum);
   ```
   Please note that the minimal signal number is 1, and the maximal signal number is 32.
   
- `int sigprocmask(int how, const sigset_t *newset, sigset_t *oldset);`

   Implement the standard `sigprocmask` function. You can use our defined `sigset_t` data type. When `newset` is `NULL`, the function only returns the original signal mask associated with the current process.
   
   You may have a look at the [kernel source](https://elixir.bootlin.com/linux/v6.14.3/source/kernel/signal.c#L3320) to see how `sys_rt_sigprocmask` and `sigset_t` are implemented.

- `int setjmp(jmp_buf env);`

   Implement the standard `sigsetjmp` in Linux. Your implementation should always preserve the signal mask.

- `void longjmp(jmp_buf env, int val);`

   Implement the standard `siglongjmp` in Linux. Your implementation should always restore the signal mask.

## Requirements and Hints

Here are some hints for you to implement the codes.

1. You must implement everything in a single assembly file called `libmini64-ext.asm`, and place it in the parent directory of `chals`, or replace the symbolic link `libmini64-ext.asm`in the `chals` directory.

1. You must compile and test your implementation using the rules defined in our `Makefile`. For example, to run `test01`, run the following commands:

   ```shell
   make test01
   ./test01
   ```

   Alternatively, you may simply run `sh testall.sh` to compile and run all the test cases.

1. You may include `libmini.inc` in your implementation.

1. To access global variables defined in your own implementation, you may need to access them using a relative address, e.g., `[rel some_variable]`.

1. To access global variables defined in `libmini64.asm` or `libmini.c`, you may need to use their relative address to gotpcrel. You can do that using the syntax:

   ```ASM
   mov [rel errno wrt ..gotpcrel], rax
   ```

1. To invoke functions implemented in the `libmini64.asm` or `libmini.c`, you may need to call its relative address to the PLT table. You can do that using the syntax:

   ```ASM
   call sys_nanosleep wrt ..plt
   ```

1. To implement `setjmp` and `longjmp`, you may need to preserve the return address and the following registers:

   ```
   rbx rbp rsp r12 r13 r14 r15 
   ```

## The Challenge Server

No challenge server for this lab. You can simply do everything in your own host.

:::warning
For Apple Chip users, you should be able to run everything in your Linux (aarch64) docker. However, if you plan to run the compiled executables, you may choose one of the following two options:

1. Install Rosetta2 on your Mac OS, and then you can run all the test case executables directly in the Linux docker.
2. Alternatively, install `qemu-user-static` package in your Linux docker and run the test case executables using `qemu-x86_64-static`
:::

## Grading

1. [10%] You pass the tests for `time` function.

   You can use `date '+%s'` on your host to check the current timestamp.

1. [10%] You pass the tests for `srand` and `grand` functions.

   The two output numbers should match and should equal the current host timestamp minus one.

1. [10%] You pass the tests for `rand`.

   The two output sequences should be identical. 

1. [20%] You pass the tests for these functions `sigemptyset`, `sigfillset`, `sigaddset`, `sigdelset`, and `sigismember`.

   There are two test cases, and you must pass both to receive full credit.
   - `fill set` should have all the bits set.
   - `emptyset` should have all the bits unset.
   - For the rest of `set` operations, the corresponding bit should be set - the numbers are printed out in hexadecimal format in the test cases.
   - For the rest of `unset` operations, the corresponding bit should be unset - the numbers are printed out in hexadecimal format in the test cases.
   - The last two bit strings output from test case #b must be identical. 
     - The bit string `sigset_t` is derived from repeated calls to `sigismember`.

1. [10%] You pass the tests for `sigprocmask` function.

   The `user mask` and `proc mask` in the test case output should be nearly identical (because some signals may be masked by the kernel).
   
   Example output:
    ```
    ===== TEST test05 =====
    ## test: sigprocmask
    backup: 0
    old vs new: 0 1d2c
    old vs new: 1c2c 1a229
    user mask: 00000000000000000001110100000100
    proc mask: 00000000000000000001110000000100 - only SIGKILL(9) can be different
    proc mask: 1c04
    ```

1. [15%] You pass the tests for `setjmp` function.

   There are two tests. You must pass both test cases to receive credit.
   - `setjmp` must return 0.
   - return address must be preserved in the `jmpbuf`, which should be pretty close to the address of the `main` function.
   - The `mask` should:
      - Be zero in test case #a.
      - Be `0x200` in test case #b, indicating that `SIGUSR1` is set in the mask.
   
   Example output:
   ```
   ===== TEST test06a =====
   ## test: setjmp
   setjmp: 0
   registers: 0 7ffd2e8d0c70 7ffd2e8d0cc0 5f5239b72110 7ffd2e8d0cd0 0 0 5f5239b72023
   main: 5f5239b72000
   mask: 0 (should be ZERO)
   ===== TEST test06b =====
   ## test: setjmp w/ sigprocmask
   setjmp: 0
   registers: 0 7ffdf2e3f910 7ffdf2e3f970 5d5f3a112140 7ffdf2e3f980 0 0 5d5f3a112056
   main: 5d5f3a112000
   mask: 200 (should have SIGUSR1 set)
   ```

1. [25%] You pass the tests for `longjmp` function.

   There are two tests. You have to pass both of them to get the points. You may simply follow the checks shown on the test case outputs.

    Example output:
    ```
    ===== TEST test07a =====
    ## test: setjmp
    setjmp: 0
    registers: 0 7ffcb5b34b50 7ffcb5b34b60 593fd0387290 7ffcb5b34b70 0 0 593fd0387168
    main: 593fd0387127
    jmp_buf mask: 200 (have SIGUSR1 set)
    This is function a ...
    This is function b ...
    This is function c ...
    process mask: a00 (have SIGUSR1 set, and only have SIGUSR2 set in the 1st time)
    setjmp: 58
    registers: 0 7ffcb5b34b50 7ffcb5b34b60 593fd0387290 7ffcb5b34b70 0 0 593fd0387168
    main: 593fd0387127
    jmp_buf mask: 200 (have SIGUSR1 set)
    This is function a ...
    This is function b ...
    This is function c ...
    process mask: 200 (have SIGUSR1 set, and only have SIGUSR2 set in the 1st time)
    ===== TEST test07b =====
    ## test: setjmp
    This is function a ...
    setjmp: 0
    process mask: 200
    This is function b ...
    process mask: a00
    This is function c ...
    process mask: a00
    This is function a ...
    setjmp: 58
    process mask: 200
    ```
