#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h> // Required for INT32_MIN/MAX if you were still using relative jump checks

void trampoline_target() {
    fprintf(stdout, "Hello from trampoline!\n\n");
}

__attribute__((constructor))
void setup_trampoline() {
    size_t nop_size = 512;
    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t map_size = page_size;

    void *mapped_addr = mmap((void *)0x0, map_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    unsigned char *addr = (unsigned char *)mapped_addr;

    if (mapped_addr == MAP_FAILED || mapped_addr != addr) {
        perror("mmap failed for address 0x0");
        return;
    }

    for (size_t i = 0; i < nop_size; i++) {
        addr[i] = 0x90;
    }

    uintptr_t target_addr = (uintptr_t)trampoline_target;

    unsigned char trampoline_code[] = {
        0x49, 0xBB,                         // movabs $addr, %r11
        0, 0, 0, 0, 0, 0, 0, 0,             // (target_addr)
        0x41, 0xFF, 0xE3                    // jmp *%r11
    };
    memcpy(&trampoline_code[2], &target_addr, sizeof(target_addr));
    memcpy(addr + nop_size, trampoline_code, sizeof(trampoline_code));
    
}

