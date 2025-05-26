# UP25 HW1

<i style="color:red">Due Date: 2025-04-28</i>

[TOC]

## System Call Hook and Logging

In this homework, you will practice library injection and system call hooking. The system call hooking mechanism is inspired by [zpoline](https://github.com/yasukata/zpoline), which won the Best Paper award at USENIX ATC 2023.

Your task is to implement an x86-64 system call hook step by step and build a logging application that tracks file-access-related activities for an arbitrary binary running on a Linux operating system using that mechanism. You will learn to intercept system calls using dynamic linking with `LD_PRELOAD`, modify executable code in memory, and handle subtle issues related to calling conventions. Although you may refer to [zpoline](https://github.com/yasukata/zpoline) for guidance, you must not directly copy its implementation.

**Part 1: Initialization Shared Object**
This shared object will be injected into the monitored binary using `LD_PRELOAD`. Once loaded by the dynamic loader, it must initialize the environment by setting up a trampoline, rewriting system call instructions, and integrating with the logging shared object.

**Part 2: Logging Shared Object**
This shared object will be loaded by the initialization shared object via the `LIBZPHOOK` environment variable. It will intercept file-access-related system calls and log their parameters and return values.

For more details, please refer to the [requirements section](#Requirements).

## Introduction

zpoline is a high-performance system call hook mechanism for Linux that intercepts system calls efficiently and exhaustively. It operates by setting up a **trampoline** at virtual address 0 and modifying the `syscall` instruction to redirect control flow, without requiring modifications to the application binary or kernel.

**Setup** involves the following steps:

1. **Binary rewriting**: The original `syscall` instruction is replaced with `callq *%rax`. The `rax` register, which holds the system call number in the x86-64 calling convention, is leveraged to point to the trampoline code at virtual address 0. This redirection ensures that when `callq *%rax` is executed, control is transferred to the trampoline.

1. **Trampoline setup**: A small piece of code (the trampoline) is placed at virtual address 0. To ensure proper redirection to the trampoline, enough `nop` instructions are inserted at the trampoline's starting location. This creates sufficient space for the `callq *%rax` to land in the trampoline logic, allowing the system call to be intercepted correctly.

1. **Load hook library**: The hook function may need shared libraries (e.g., `fprintf` from libc) for tasks like logging. However, if a shared library function triggers a system call, the system call will be redirected to the trampoline, causing recursion (e.g., hook function → shared library → replaced system call → trampoline → hook function). To prevent this, the hook library is loaded in a separate namespace using `dlmopen`, ensuring that shared libraries are used without triggering the system call redirection again.

**For more details**, refer to the [zpoline paper](https://www.usenix.org/conference/atc23/presentation/yasukata) and the source code documentation.

## Requirements

### Prerequisites

Before starting development, set `/proc/sys/vm/mmap_min_addr` to `0`:

```sh
sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"
```

### Part 1: Initialization Shared Object

- Complete all **testing requirements** for each step in the [step guide](#Step-by-Step-Guide-for-Part-1).
- Following the step guide should produce three shared objects: `libzpoline.so.1`, `libzpoline.so.2`, and `libzpoline.so`.
- The testing requirements for each step are independent and do not carry over to later steps, ensuring correctness at each stage without enforcing previous behaviors.
  - For example, you might be asked to hardcode certain outputs in one test case for testing purposes. However, in later test cases, you must remove the hardcoded code to ensure the output matches the expected answer.

### Part 2: Logging Shared Object

#### Library Usage

Implement a logging shared object named `logger.so`. This shared object will be loaded by `libzpoline.so` via the `LIBZPHOOK` environment variable to define the hooking behavior.

Usage:

```sh
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so command [arg1 arg2 ...]
```

#### System Call Logging List

Your hook library must intercept and log the following system calls to `stderr`. Each log entry must be emitted **after** the actual system call is performed, showing the result (`= return_value`). Use the exact formatting specified below to ensure consistency with TA tests.

1. `openat`

    Log the `openat` system call in the following format:

    ```
    [logger] openat(DIRFD, "FILENAME", 0xFLAGS, MODE) = RETURN_VALUE
    ```

    - Print `AT_FDCWD` if the `DIRFD` is `-100`. Otherwise, print the integer directly.
    - Print `FILENAME` in double quotes.
    - Print `FLAGS` in hexadecimal with a `0x` prefix. Do not decode into symbolic constants.
    - Print `MODE` in octal with a leading `0`. Use the format specifier `%#o`.
    - Print `RETURN_VALUE` the return value of the `openat` call as-is.

    Example:
    
    ```
    [logger] openat(AT_FDCWD, "/etc/hosts", 0x80000, 0666) = 3
    ```

1. `read`
   Log the read content as a string literal, escaping non-printable characters and truncating after the first 32 bytes. The format is:

   ```
   [logger] read(FD, "ESCAPED_CONTENT"..., COUNT) = RETURN_VALUE
   ```

   - `ESCAPED_CONTENT` includes escaped `\t`, `\n`, and `\r`, as well as non-printable bytes represented as `\xhh`, where `hh` is two lowercase hexadecimal digits (e.g., `\x1b`).
   - If more than 32 bytes were read, append `...` after the string.
   - `COUNT` is the original count argument to `read`.

   Example:

   ```
   [logger] read(3, "###\n### Sample Wget initializati"..., 4096) = 4096
   ```

1. `write`
   Similar to `read`, but logs the buffer that was written:

   ```
   [logger] write(FD, "ESCAPED_CONTENT"..., COUNT) = RETURN_VALUE
   ```

   - Escape and truncate the buffer as in `read`.
   - The same format is used regardless of the actual content.

   Example:

   ```
   [logger] write(4, "<!doctype html><html itemscope=""..., 4096) = 4096
   ```

1. `connect`
   Log the address of the target socket using a format appropriate to the socket type:

   ```
   [logger] connect(FD, "ADDRESS:PORT", ADDRLEN) = RETURN_VALUE
   ```

   - For IPv4: use dotted-quad format (e.g., `"8.8.8.8:53"`).
   - For IPv6: use the full IPv6 string (e.g., `"2404:6800:4012:6::2004:443"`).
   - For UNIX domain sockets: use `"UNIX:SOCKET_PATH"`.
   - `ADDRLEN` is the third argument passed to `connect`.

   Example:

   ```
   [logger] connect(3, "142.250.198.68:80", 16) = 0
   [logger] connect(3, "UNIX:/tmp/socket", 110) = -1
   ```

1. `execve`
   Log the execution target without expanding `argv` or `envp`:

   ```
   [logger] execve("FILENAME", ARGV_PTR, ENVP_PTR)
   ```

   - `FILENAME` must be quoted.
   - Show raw pointer values for `argv` and `envp` (e.g., `0x7ffd...`).
   - This log should be emitted **before** the actual `execve` system call is performed.

   Example:

   ```
   [logger] execve("/usr/bin/wget", 0x56c79d197998, 0x56c7a26f9738)
   ```

## Step-by-Step Guide for Part 1

### Step 1: Set Up the Trampoline

The trampoline is a small code segment placed in a designated memory region that serves as the controlled entry point for your hook. In the zpoline-inspired mechanism, this region must start at address `0x0`.

To set up the trampoline:

1. Allocate a writable and executable memory region starting at address `0x0`.
1. Fill the first 512 bytes with `nop` instructions (each `nop` is a 1-byte opcode).
1. Starting at byte 512 (0-indexed), write the assembly code for your trampoline.

For example, to place an `int3` instruction immediately after the `nop`s:

```cpp
unsigned char *addr = 0x0; // Assume memory is properly mapped
addr[512] = 0xCC;          // 'int3'
```

To test the trampoline:

- Create a function pointer that points to an address within the first 512 bytes.
- Call this function pointer to verify that it correctly jumps to the trampoline code.

Once the trampoline behaves as expected, convert your implementation into a shared library that sets up the trampoline when loaded via `LD_PRELOAD`. There's no need to jump directly to the trampoline from your shared library - just ensure it is properly established.

:::info
To execute custom initialization code automatically when your shared library is loaded, use the **`__attribute__((constructor))`** function attribute. This constructor runs before control returns from `dlopen()`, or during program startup when preloaded, making it ideal for tasks like setting up hooks or patching memory.
:::

#### Testing Requirements

- The name of the shared library should be `libzpoline.so.1`.
- Make sure the first 512 bytes are `nop`.
- The memory region starting at address 0x0 should be **readable** and **executable**.
- The shared library must print a message upon entering the trampoline:
  ```plaintext
  Hello from trampoline!
  ```
- Our test cases will preload your shared library to verify that the trampoline is set up correctly. See [example 1](#ex1) for the expected results.

### Step 2: Rewrite Code

In this step, you will modify the target code to redirect system calls through the trampoline you established in [Step 1](#Step-1-Set-Up-the-Trampoline). This involves identifying executable memory regions, replacing instructions, and ensuring correct argument handling.

To rewrite the code:

1. Retrieve memory region information from `/proc/self/maps` to identify executable segments where system calls may occur.
1. Replace every `syscall` instruction in these regions with `call *%rax`. This change redirects system calls to the trampoline, which then transfers control to your handler function.
1. In your handler function, re-insert a `syscall` instruction to perform the original system call.

:::info
You don't need to handle `[vdso]` and `[vsyscall]`.
:::

:::warning
Once system calls are redirected, any function that internally issues a system call (e.g., `printf`) will also trigger the hook.

Ensure your handler **does not call functions whose system calls have been rewritten to go through the hook**, particularly most `libc` functions, as this will result in infinite recursion.
:::

If the binary rewrite is successful, the modified program should continue to function normally, even when your shared library is preloaded.

To confirm that your binary rewrite is successful, we will validate it by checking whether your implementation can modify system call behavior. By altering specific system call arguments, we can observe the effects and verify that the system call is indeed being intercepted.

Since modifying system call behavior directly in assembly can be complex, we recommend implementing this logic in C for better clarity and flexibility.

To achieve this:

1. Write assembly code that prepares arguments and calls a C handler function:

   ```cpp
   int64_t handler(int64_t, int64_t, int64_t, int64_t,
                   int64_t, int64_t, int64_t);

   void trampoline() {
     /* ... */

     asm volatile(
         /* Write assembly to prepare arguments here */
         "call handler \t\n"
     );

     /* ... */
   }
   ```

1. Provide a C function that issues the system call, so you can issue a system call in your handler function:

   ```cpp
   extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t,
                                  int64_t, int64_t, int64_t);

   void __raw_asm() {
     asm volatile("trigger_syscall: \t\n"
                  /* Write assembly to prepare arguments here */
                  "  syscall \t\n"
                  "  ret \t\n");
   }
   ```

:::warning
***Updated on Apr. 16***
Zpoline is responsible for preserving volatile registers before transferring control from raw assembly to any C function.

According to the x86-64 ABI, a system call must preserve the values of all general-purpose registers **except `rax`, `rcx`, and `r11`**.

If registers such as `rdi`, `rsi`, `rdx`, `r8`, `r9`, or `r10` are not saved and restored, the hook function may unintentionally corrupt register values expected by the original code. This can lead to some faults that may not appear immediately, but only after several system calls, depending on the program’s register usage.

To avoid such faults, Zpoline must ensure these registers are saved at the assembly boundary and restored after the hook returns.
:::

#### **Testing Requirement**

- The name of the shared library should be `libzpoline.so.2`.

- Your shared library should function as a **Leetspeak Decoding Hook**. When your hook intercepts a `write` syscall (number 1) targeting `stdout` (file descriptor 1), it must perform a **leet-to-text conversion** before forwarding the output.

- The translation must follow the mapping:

  | Leet      | 0   | 1   | 2   | 3   | 4   | 5   | 6   | 7   |
  | --------- | --- | --- | --- | --- | --- | --- | --- | --- |
  | Character | o   | i   | z   | e   | a   | s   | g   | t   |

- For example, running this command:

  ```bash
  $ LD_PRELOAD=./libzpoline.so.2 /usr/bin/echo '7h15 15 4 l337 73x7'
  ```

  Should produce the output:

  ```plaintext
  this is a leet text
  ```

- See [example 2-1](#ex2-1) and [example 2-2](#ex2-2) for testing methods and expected results.

### Step 3: Load the Hook Library

**Definitions**

- The **init library** refers to the original shared library created in [Step 1](#Step-1-Set-Up-the-Trampoline) and [Step 2](#Step-2-Rewrite-Code).
- The **hook library** is a new shared library that contains the hook function. It is loaded into a separate namespace by the **init library** using `dlmopen` to prevent recursion when calling libc functions inside the hook.

Your **init library** will be tested with various **hook libraries** implemented by TAs. To ensure compatibility, both libraries must follow a defined interface.

- The **init library** retrieves the **hook library** name from the `LIBZPHOOK` environment variable.

- The **hook library** must expose a function called `__hook_init` with the following signature:

  ```c
  typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t,
                                       int64_t, int64_t, int64_t);

  void __hook_init(const syscall_hook_fn_t trigger_syscall,
                   syscall_hook_fn_t *hooked_syscall);
  ```

In `syscall_hook_fn_t`, each argument maps to a register following the x86-64 system call calling convention, ordered as follows:

- `%rdi` to `%r9`: Hold the first six integer arguments.
- `%rax`: Holds the syscall number.

The return value should be `%rax` returned from the actual system call.

The `__hook_init` arguments are defined as follows:

- **`trigger_syscall`**: Provided by the **init library**, this function pointer points to a C function that directly issues system calls. The **hook library** should retain this pointer to invoke system calls when needed.
- **`hooked_syscall`**: A pointer to a function pointer provided by the **init library**. This allows the **hook library** to modify the target function pointer itself, redirecting system calls to a custom hook. The **init library** may initially set `*hooked_syscall` to `trigger_syscall` as a default. When `__hook_init` is called, the **hook library** replaces `*hooked_syscall` with its own hook function, allowing the **init library** to intercept system calls through this modified pointer.

The following is a sample implementation of a **hook library**:

```c
#include <stdint.h>
#include <stdio.h>

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t);

static syscall_hook_fn_t original_syscall = NULL;

static int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx,
                               int64_t r10, int64_t r8, int64_t r9,
                               int64_t rax) {
  fprintf(stderr, "Intercepted syscall: %ld\n", rax);
  return original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
}

void __hook_init(const syscall_hook_fn_t trigger_syscall,
                 syscall_hook_fn_t *hooked_syscall) {
  original_syscall = trigger_syscall;
  *hooked_syscall = syscall_hook_fn;
}
```

:::warning
The **init library** is responsible for ensuring proper stack alignment before invoking the function pointer stored in `hooked_syscall`.

According to the x86-64 ABI, the stack must be aligned to a **16-byte boundary**.

Misaligned stacks can cause undefined behavior or crashes when invoking functions in the standard C library from within the hook function referenced by `hooked_syscall`.
:::

#### Testing Requirement

- The name of the shared library should be `libzpoline.so`.

- TAs will provide various hook libraries for testing your init library. See [example 3](#ex3) for testing methods and expected results.

## Examples

Here we provide some running examples. Please notice that the results presented here could be different from your runtime environment. You may simply ensure that the behavior is expected and the output format is correct.

Here are all the sample files for the example below. Please download the tgz file from this [link](https://up.zoolab.org/unixprog/hw01/examples.tgz) and extract them.

### ex1

- input: `./ex1`

- output:

  ```
  Segmentation fault (core dumped)
  ```

- input: `LD_PRELOAD=./libzpoline.so.1 ./ex1`

- output:

  ```
  Trying to call function at address: 0
  Hello from trampoline!

  Trying to call function at address: 177
  Hello from trampoline!

  Trying to call function at address: 285
  Hello from trampoline!

  Trying to call function at address: 326
  Hello from trampoline!

  Trying to call function at address: 511
  Hello from trampoline!
  ```

### ex2-1

- input:

  ```
  LD_PRELOAD=./libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}'
  ```

- output:

  ```
  uphw{this_is_a_simple_flag_from_zoolab}
  ```

### ex2-2

- input: `LD_PRELOAD=./libzpoline.so.2 cat ex2-2.txt`

- output:

  ```
  **this article has been encoded in leet.**

  if you can read this, you probably have seen this form of writing before. in case you haven't, this is a common way of disguising text by replacing letters with numbers.

  However, the idea behind this article is to see if it can be **unleeted** back to a readable form. if the reverse process does not reveal a compietely coherent english sentence, there may be an error in the leet conversion.

  if you've decoded this article and it is completely readable, then the leet translation is correct. otherwise, something went wrong.

  Good luck unleeting this!
  ```

### ex3

- input: `LD_PRELOAD=./libzpoline.so LIBZPHOOK=./libex3hook.so ./ex3`
- output:
  ```
  Intercepted syscall: 1
  Hello, world!
  Intercepted syscall: 60
  ```

### ex4-1

- input: `LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so touch main.c`
- output:
  ```
  [logger] openat(AT_FDCWD, "/usr/lib/locale/locale-archive", 0x80000, 0) = 3
  [logger] openat(AT_FDCWD, "/usr/share/locale/locale.alias", 0x80000, 0) = 3
  [logger] read(3, "# Locale name alias data base.\n#"..., 4096) = 2996
  [logger] read(3, "", 4096) = 0
  [logger] openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_CTYPE", 0x80000, 0) = -2
  [logger] openat(AT_FDCWD, "/usr/lib/locale/C.utf8/LC_CTYPE", 0x80000, 0) = 3
  [logger] openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", 0x0, 0) = 3
  [logger] openat(AT_FDCWD, "main.c", 0x941, 0666) = 3
  ```

### ex4-2

- input: `LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cat /etc/hosts`
- output:
  ```
  [logger] openat(AT_FDCWD, "/usr/lib/locale/locale-archive", 0x80000, 0) = 3
  [logger] openat(AT_FDCWD, "/usr/share/locale/locale.alias", 0x80000, 0) = 3
  [logger] read(3, "# Locale name alias data base.\n#"..., 4096) = 2996
  [logger] read(3, "", 4096) = 0
  [logger] openat(AT_FDCWD, "/usr/lib/locale/C.UTF-8/LC_CTYPE", 0x80000, 0) = -2
  [logger] openat(AT_FDCWD, "/usr/lib/locale/C.utf8/LC_CTYPE", 0x80000, 0) = 3
  [logger] openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", 0x0, 0) = 3
  [logger] openat(AT_FDCWD, "/etc/hosts", 0x0, 0) = 3
  [logger] read(3, "127.0.0.1\tlocalhost\n::1\tlocalhos"..., 131072) = 174
  127.0.0.1       localhost
  ::1     localhost ip6-localhost ip6-loopback
  fe00::0 ip6-localnet
  ff00::0 ip6-mcastprefix
  ff02::1 ip6-allnodes
  ff02::2 ip6-allrouters
  172.17.0.2      278395f29d37
  [logger] write(1, "127.0.0.1\tlocalhost\n::1\tlocalhos"..., 174) = 174
  [logger] read(3, "", 131072) = 0
  ```

### ex5

- input: `LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so wget http://www.google.com -q -t 1`
- output:
  ```
  ...
  [logger] openat(AT_FDCWD, "/etc/wgetrc", 0x0, 0) = 3
  [logger] read(3, "###\n### Sample Wget initializati"..., 4096) = 4096
  [logger] read(3, "ruct = off\n\n# You can turn on re"..., 4096) = 846
  [logger] read(3, "", 4096) = 0
  ...
  [logger] openat(AT_FDCWD, "/etc/hosts", 0x80000, 0) = 3
  [logger] read(3, "127.0.0.1\tlocalhost\n::1\tlocalhos"..., 4096) = 174
  [logger] read(3, "", 4096) = 0
  [logger] connect(3, "8.8.8.8:53", 16) = 0
  [logger] openat(AT_FDCWD, "/etc/gai.conf", 0x80000, 0) = 3
  [logger] read(3, "# Configuration for getaddrinfo("..., 4096) = 2584
  [logger] read(3, "", 4096) = 0
  [logger] connect(3, "142.250.198.68:0", 16) = 0
  [logger] connect(3, "2404:6800:4012:6::2004:0", 28) = -101
  [logger] connect(3, "142.250.198.68:80", 16) = 0
  [logger] write(3, "GET / HTTP/1.1\r\nHost: www.google"..., 129) = 129
  [logger] read(3, "HTTP/1.1 200 OK\r\nDate: Sun, 06 A"..., 511) = 511
  [logger] read(3, " SAMEORIGIN\r\nSet-Cookie: AEC=AVc"..., 512) = 512
  [logger] read(3, " none\r\nVary: Accept-Encoding\r\nTr"..., 60) = 60
  ...
  [logger] openat(AT_FDCWD, "index.html", 0x241, 0666) = 4
  [logger] read(3, "3d01\r\n", 6) = 6
  [logger] read(3, "<!doctype html><html itemscope=""..., 8192) = 5911
  [logger] write(4, "<!doctype html><html itemscope=""..., 4096) = 4096
  [logger] write(4, "7px !important;text-align:right}"..., 1815) = 1815
  ...
  ```

### ex6

- input: `LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")'`
- output:
  ```
  [logger] openat(AT_FDCWD, "/usr/lib/python3.11", 0x90800, 0) = 3
  ...
  [logger] execve("/bin/sh", 0x7ffd24951830, 0x7ffd249520f8)
  [logger] execve("/usr/bin/wget", 0x56c79d197998, 0x56c7a26f9738)
  ...
  [logger] openat(AT_FDCWD, "/etc/wgetrc", 0x0, 0) = 3
  [logger] read(3, "###\n### Sample Wget initializati"..., 4096) = 4096
  [logger] read(3, "ruct = off\n\n# You can turn on re"..., 4096) = 846
  [logger] read(3, "", 4096) = 0
  ...
  [logger] openat(AT_FDCWD, "/etc/hosts", 0x80000, 0) = 3
  [logger] read(3, "127.0.0.1\tlocalhost\n::1\tlocalhos"..., 4096) = 174
  [logger] read(3, "", 4096) = 0
  [logger] connect(3, "8.8.8.8:53", 16) = 0
  [logger] openat(AT_FDCWD, "/etc/gai.conf", 0x80000, 0) = 3
  [logger] read(3, "# Configuration for getaddrinfo("..., 4096) = 2584
  [logger] read(3, "", 4096) = 0
  [logger] connect(3, "142.250.198.68:0", 16) = 0
  [logger] connect(3, "2404:6800:4012:6::2004:0", 28) = -101
  [logger] connect(3, "142.250.198.68:80", 16) = 0
  [logger] write(3, "GET / HTTP/1.1\r\nHost: www.google"..., 129) = 129
  [logger] read(3, "HTTP/1.1 200 OK\r\nDate: Sun, 06 A"..., 511) = 511
  [logger] read(3, " SAMEORIGIN\r\nSet-Cookie: AEC=AVc"..., 512) = 512
  [logger] read(3, " none\r\nVary: Accept-Encoding\r\nTr"..., 60) = 60
  ...
  [logger] openat(AT_FDCWD, "index.html", 0x241, 0666) = 4
  [logger] read(3, "3d01\r\n", 6) = 6
  [logger] read(3, "<!doctype html><html itemscope=""..., 8192) = 5911
  [logger] write(4, "<!doctype html><html itemscope=""..., 4096) = 4096
  [logger] write(4, "7px !important;text-align:right}"..., 1815) = 1815
  ...
  ```

## Homework Submission

Please include a `Makefile` that compiles your source code. Your code must be compiled by simply running the `make` command. Submit your work as a compressed archive in the format described below.

- **Due Date**: 2025-04-28 15:10
- **Filename**: `{studentID}_hw1.tar` or `{studentID}_hw1.tgz`
- **Archive Structure**:
  ```
  +---{studentID}_hw1
  |    Makefile
  |    other files...
  ```

## Grading

1. \[60%\] Your shared library has the correct output for all test cases listed in the [examples section](#Examples).
   - 5 pts for `ex2-1` `ex2-2` `ex4-1` `ex4-2`
   - 10 pts for the others
1. \[40%\] Hidden case. Hidden test cases will be revealed on the day of the demo.
   - 10 pts for each testcase
   - [Link](https://md.zoolab.org/d1I7ASsAT3qufAGcOHrGhQ?view#) (Updated on Apr. 28)

## Hints

1. To catch and debug code inside a `__attribute__((constructor))` function—or any function within a shared library—you can use specific GDB commands along with an environment variable to break execution at the start of the constructor function:

   ```bash
   $ gdb /lib64/ld-linux-x86-64.so.2
   (gdb) set environment ZDEBUG=1
   (gdb) r --preload /path/to/library.so.1 ./your_program
   ```

   Additionally, you may need to insert a software breakpoint using `int3` at the beginning of the constructor function:

   ```c
   void init() {
       ...
       if (getenv("ZDEBUG")) {
           asm("int3");
       }
       ...
   }
   ```

1. Your shared library may have to make the region _writable_ by using the [mprotect(2)](https://man7.org/linux/man-pages/man2/mprotect.2.html) function before you modify the values in the executable region.

1. You can link against the Capstone library for disassembling. By default, Capstone stops at invalid instructions. However, with `SKIPDATA` mode enabled, it bypasses data regions and continues disassembling. This is particularly useful when code and data are mixed in the executable region.

1. System calls and C functions follow different calling conventions, so you must ensure arguments are passed correctly when transitioning between them.

   > The interface between the C library and the Linux kernel is the same as for user-level applications with the following differences:
   >
   > 1. User-level applications use `%rdi`, `%rsi`, `%rdx`, **`%rcx`**, `%r8`, and `%r9` to pass integer arguments. The kernel interface uses `%rdi`, `%rsi`, `%rdx`, **`%r10`**, `%r8`, and `%r9`.
   > 1. ...
   >
   > - _Reference: Appendix A.2.1, Calling Conventions_, [x86-64 ABI Specification](https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build)

1. System calls like `clone` and `clone3` allow the caller to specify the stack address for the child process or thread. When `CLONE_VM` is set, the child shares the same address space as the parent but uses a separate stack region, which is typically allocated and initialized by the parent. If the `syscall` instruction is replaced with `call *%rax`, the CPU pushes a return address onto the current stack. In the child thread, however, this stack may not contain a valid return address, since it starts with a freshly provided stack pointer and does not inherit the parent's stack contents.

   - To ensure that the child thread can safely return after the `call`, the return address must be manually pushed onto the top of the new stack before invoking the `clone` system call when `CLONE_VM` is used.
   - When `CLONE_VM` is not set (e.g., in `fork`-like usage), the kernel duplicates the parent's memory, including the stack, so the return address is preserved automatically and no manual intervention is necessary.
   - For reference, zpoline handles this issue by explicitly adjusting the child's stack to include the return address before executing the system call, as shown [here](https://github.com/yasukata/zpoline/blob/8f89b409a55f6426fd5751abccced634853795e4/main.c#L242).
