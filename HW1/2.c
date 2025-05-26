#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <dis-asm.h>
#include <sched.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <linux/sched.h> // Needed for struct clone_args

#define CLONE_SYS_NUM 56
#define CLONE3_SYS_NUM 435

extern void syscall_addr(void);
extern void syscall_1(void);
extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void trampoline(void);

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
typedef void (*__hook_init)(const syscall_hook_fn_t trigger_syscall, syscall_hook_fn_t *hooked_syscall);

struct disassembly_state {
    char *code;
    size_t off;
};

void __raw_asm(){
    asm volatile (
        ".globl trigger_syscall \t\n"
        "trigger_syscall: \t\n"
        "  movq 8(%rsp), %rax \t\n"
        "  movq %rcx, %r10 \t\n" /* hint 4 in spec : System calls and C functions follow different calling conventions */
        ".globl syscall_addr \t\n"
        "syscall_addr: \t\n"
        "  syscall \t\n"
        "  ret \t\n"
    );

    asm volatile (
        ".globl trampoline \t\n"
        "trampoline: \t\n"

        // handle vfork
        "  cmpq $0x3a, %rax \t\n"
        "  jne trampoline_normal \t\n"
        "  addq $128, %rsp \n\t"
        "  popq %rsi \t\n"
        ".globl syscall_1 \t\n"
        "syscall_1: \t\n"
        "  syscall \t\n"
        "  pushq %rsi \t\n"
        "  retq \t\n"
        "trampoline_normal: \t\n"

        // rt_sigreturn
        "  cmpq $15, %rax \n\t" 
	    "  je do_rt_sigreturn \n\t"
        
        // setting stack
        "  pushq %rbp \t\n"
        "  movq %rsp, %rbp \t\n"

        // 16 byte alignment for function calls
        "  andq $-16, %rsp \t\n"
        
        // preserve registers that might be changed
        "  pushq %rdi \t\n"  
        "  pushq %rsi \t\n"
        "  pushq %rdx \t\n"
        "  pushq %r8 \t\n"
        "  pushq %r9 \t\n" 
        "  pushq %r10 \t\n"  
        "  pushq %r12 \t\n"
        
        // system call hook
        "  pushq 136(%rbp) \t\n"  // preserve return address
        "  pushq %rax \t\n"
        "  pushq %r10 \t\n"
        "  movq %r10, %rcx \t\n"
        "  callq syscall_hook@plt \t\n"
        
        "  popq %r10 \t\n"
        "  addq $16, %rsp \t\n"  // discard arg7 and arg8
        
        // revert register value
        "  popq %r12 \t\n"
        "  popq %r10 \t\n"
        "  popq %r9 \t\n"
        "  popq %r8 \t\n"
        "  popq %rdx \t\n"
        "  popq %rsi \t\n"
        "  popq %rdi \t\n"
        
        "  leaveq \t\n"  // clear stack frame
        
        "  addq $128, %rsp \t\n"
        "  retq \t\n"

        // rt_sigreturn
        "do_rt_sigreturn:"
        "addq $136, %rsp \n\t"
        "jmp syscall_addr \n\t"
    );
}

static syscall_hook_fn_t hook_fn = trigger_syscall;

long syscall_hook(int64_t rdi, int64_t rsi,int64_t rdx, int64_t __rcx __attribute__((unused)), int64_t r8, int64_t r9, int64_t r10, int64_t rax, int64_t retptr) {
    // handle for clone (syscall num = 56)
    if (rax == CLONE_SYS_NUM) {
        if (rdi & CLONE_VM) { // create new thread
            rsi -= sizeof(uint64_t);
            *((uint64_t *) rsi) = retptr;  // preserve return ptr
        }
    }

    // handle for clone3 (syscall num = 435)
    if (rax == CLONE3_SYS_NUM) {        
        struct clone_args *cl_args = (struct clone_args *) (uintptr_t) rdi;
        if (cl_args->flags & CLONE_VM) {
            cl_args->stack_size -= sizeof(uintptr_t);
            *((uintptr_t *)(cl_args->stack + cl_args->stack_size)) = retptr;
        }
    }

    if (rax == __NR_write && rdi == 1) {
        char *buf = (char *)rsi;
        size_t count = rdx;
        for (size_t i = 0; i < count; ++i) {
            switch (buf[i]) {
                case '0': buf[i] = 'o'; break;
                case '1': buf[i] = 'i'; break;
                case '2': buf[i] = 'z'; break;
                case '3': buf[i] = 'e'; break;
                case '4': buf[i] = 'a'; break;
                case '5': buf[i] = 's'; break;
                case '6': buf[i] = 'g'; break;
                case '7': buf[i] = 't'; break;
            }
        }
    }

    return hook_fn(rdi, rsi, rdx, r10, r8, r9, rax);
}

#include <string.h> // Include string.h for memcmp

static int do_rewrite(void *data, enum disassembler_style style ATTRIBUTE_UNUSED, const char *fmt, ...) {
    struct disassembly_state *s = (struct disassembly_state *) data;
    char buf[4096];
    va_list arg;

    va_start(arg, fmt);
    vsnprintf(buf, sizeof(buf), fmt, arg);
    va_end(arg);

    // use %rsp and offset < 0
    const char* rsp_pos = strstr(buf, "(%rsp)");
    bool starts_with_minus = (memcmp(buf, "-", 1) == 0);
    bool is_negative_rsp_offset = (rsp_pos != NULL) && starts_with_minus;

    bool handled = false;

    if (is_negative_rsp_offset) {
        handled = true;
        int32_t off;
        sscanf(buf, "%x(%%rsp)", &off);

        if (off >= -0x80) {
            if (off <= -0x78) {
                assert(0);
            } 
            else {
                uint8_t off_byte = (uint8_t)(off & 0xff);
                uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);

                int i = -1;
                while (++i < 16) {
                    if (ptr[i] == 0x24 && ptr[i + 1] == off_byte) {
                        ptr[i + 1] = ptr[i + 1] - 8;
                        break;
                    }
                }
            }
        } 

    } else {

        bool is_syscall_instr = (memcmp(buf, "syscall", 7) == 0);
        bool is_sysenter_instr = (memcmp(buf, "sysenter", 8) == 0);

        // replace syscall and sysenter with callq *%rax 
        if (is_syscall_instr || is_sysenter_instr) { 
            handled = true;
            uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);

            bool is_at_hook_address = (((uintptr_t) ptr == (uintptr_t) syscall_addr) || ((uintptr_t) ptr == (uintptr_t) syscall_1));  // should not replace system call hook

            if (!is_at_hook_address) {   // replaced with call %rax
                *ptr = 0xff;
                *(ptr + 1) = 0xd0;
            }
        }
    }

    return 0;
}

static void disassemble_and_rewrite(char *code, size_t code_size, int mem_prot) {
    struct disassembly_state s = { .code = code, .off = 0 }; 
    disassemble_info disasm_info = { 0 };

    mprotect(code, code_size, PROT_WRITE | PROT_READ | PROT_EXEC);

    init_disassemble_info(&disasm_info, &s, (fprintf_ftype) printf, do_rewrite);
    
    disasm_info.arch = bfd_arch_i386;
	disasm_info.mach = bfd_mach_x86_64;
	disasm_info.buffer = (bfd_byte *) code;
	disasm_info.buffer_length = code_size;
    disasm_info.buffer_vma = (uintptr_t)code;

    disassemble_init_for_target(&disasm_info);
    disassembler_ftype disasm;

    disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);

    if (!disasm) { // Check if disassembler function is valid
        fprintf(stderr, "Failed to get disassembler function.\n");
        mprotect(code, code_size, mem_prot); // Restore original protection
        return;
    }

    for (; s.off < code_size; ) {
        int bytes_disassembled = disasm((uintptr_t)code + s.off, &disasm_info);

        if (bytes_disassembled > 0) {
            s.off += bytes_disassembled;
        } 
        else {
            s.off++; // Increment offset by 1 to potentially skip invalid byte(s)
        }
    }

    mprotect(code, code_size, mem_prot);
}

static int parse_permissions(const char *perm_str) {
    int protection = PROT_NONE;
    if (strchr(perm_str, 'r')) {
        protection |= PROT_READ;
    } 
    if (strchr(perm_str, 'w')) {
        protection |= PROT_WRITE;
    }
    if (strchr(perm_str, 'x')) {
        protection |= PROT_EXEC;
    } 
    return protection;
}

static void rewrite_code(void)
{
    FILE *mem_info = fopen("/proc/self/maps", "r");
    if (!mem_info) {
        perror("fopen /proc/self/maps failed");
        return;
    }

    char buf[4096];

    while (fgets(buf, sizeof(buf), mem_info) != NULL) {
        // do not touch stack, vdso, and vsyscall
        if (((strstr(buf, "[stack]") == NULL) && (strstr(buf, "[vdso]") == NULL) && (strstr(buf, "[vsyscall]") == NULL))) {
            uintptr_t from, to;
            char perms[5];

            // Format: address_start-address_end permissions offset device inode pathname
            if (sscanf(buf, "%" PRIxPTR "-%" PRIxPTR " %4s", &from, &to, perms) == 3) {
                int mem_prot = parse_permissions(perms);
                // rewrite code if the memory is executable 
                if (mem_prot & PROT_EXEC) {
                    // ensure range is valid and not the trampoline page itself (at address 0)
                    if (to > from && from != 0) {
                        disassemble_and_rewrite((char *) from, (size_t) (to - from), mem_prot);
                    }
                }
            }
        }
    }

    fclose(mem_info);
}

static void setup_trampoline(void) {
    // Use MAP_FIXED_NOREPLACE first, fallback to MAP_FIXED
    void *mmap_mem = mmap((void*)0x0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE, -1, 0);
    if (mmap_mem == MAP_FAILED) {

        mmap_mem = mmap((void*)0x0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        if (mmap_mem == MAP_FAILED) {
            perror("mmap for trampoline failed");
            exit(1);
        }
        
    }
    if (mmap_mem != (void*)0x0) {

        fprintf(stderr, "Error: Failed to map trampoline at address 0x0.\n");
        munmap(mmap_mem, 0x1000);
        exit(1);
    }

    // fill noop
    for (size_t i = 0; i < 512; i++) {
        ((uint8_t *) mmap_mem)[i] = 0x90;
    }

    size_t current_offset = 512; 

    uint8_t sub_rsp_bytes[] = { 0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00 };
    uint8_t movabs_r11_opcode[] = { 0x49, 0xbb };
    uint8_t jmp_r11_bytes[] = { 0x41, 0xff, 0xe3 };

    // preserve redzone (sub $0x80, %rsp)
    memcpy((uint8_t *)mmap_mem + current_offset, sub_rsp_bytes, sizeof(sub_rsp_bytes));
    current_offset += sizeof(sub_rsp_bytes);

    // movabs addr, %r11
    memcpy((uint8_t *)mmap_mem + current_offset, movabs_r11_opcode, sizeof(movabs_r11_opcode));
    current_offset += sizeof(movabs_r11_opcode);

    uint64_t hook_addr = (uint64_t) trampoline;
    memcpy((uint8_t *)mmap_mem + current_offset, &hook_addr, sizeof(hook_addr));
    current_offset += sizeof(hook_addr);

    // jmp  *%r11
    memcpy((uint8_t *)mmap_mem + current_offset, jmp_r11_bytes, sizeof(jmp_r11_bytes));
    current_offset += sizeof(jmp_r11_bytes);

    mprotect(0, 0x1000, PROT_EXEC);
}

__attribute__((constructor)) static void __zpoline_init(void) {
    setup_trampoline();
    rewrite_code();
}