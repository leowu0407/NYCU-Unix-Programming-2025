section .data
seed dq 0

section .text

global time
global set_mocked_timestamp
global srand
global grand
global rand
global sigemptyset
global sigfillset
global sigaddset
global sigdelset
global sigismember
global sigprocmask
global setjmp
global longjmp

time:
    mov rax, 201
    xor rdi, rdi
    syscall
    ret

set_mocked_timestamp:
    mov [rel seed], rdi
    ret

srand:
    mov eax, edi
    sub rax, 1
    mov [rel seed], rax
    ret

grand:
    mov rax, [rel seed]
    ret

rand:
    mov rax, [rel seed]
    mov rbx, 6364136223846793005
    mul rbx
    inc rax
    mov [rel seed], rax
    shr rax, 33
    ret

sigemptyset:
    mov qword [rdi], 0
    xor rax, rax
    ret

sigfillset:
    mov rax, -1
    mov [rdi], rax
    xor rax, rax
    ret

sigaddset:
    cmp rsi, 1
    jl invalid_signal
    cmp rsi, 32
    jg invalid_signal
    mov rax, 1
    mov rcx, rsi
    dec rcx
    shl rax, cl
    or qword [rdi], rax
    xor rax, rax
    ret

sigdelset:
    cmp rsi, 1
    jl invalid_signal
    cmp rsi, 32
    jg invalid_signal
    mov rax, 1
    mov rcx, rsi
    dec rcx
    shl rax, cl
    not rax
    and qword [rdi], rax
    xor rax, rax
    ret

sigismember:
    cmp rsi, 1
    jl invalid_signal
    cmp rsi, 32
    jg invalid_signal
    mov rax, 1
    mov rcx, rsi
    dec rcx
    shl rax, cl
    test qword [rdi], rax
    setnz al
    movzx rax, al
    ret

invalid_signal:
    mov rax, -1
    ret

sigprocmask:
    mov r10, 8
    mov rax, 14
    syscall
    ret

setjmp:
    mov [rdi + 0], rbx
    mov [rdi + 8], rbp
    mov [rdi + 16], rsp
    mov [rdi + 24], r12
    mov [rdi + 32], r13
    mov [rdi + 40], r14
    mov [rdi + 48], r15

    mov rax, [rsp]
    mov [rdi + 56], rax

    lea rdx, [rdi + 64]

    push rdi

    xor edi, edi
    xor esi, esi
    call sigprocmask

    pop rdi

    xor eax, eax

    ret

longjmp:
    push rsi
    push rdi
    lea rsi, [rdi + 64] 
    mov rdi, 2          
    xor rdx, rdx             
    call sigprocmask
    pop rdi
    pop rsi

    mov rbx, [rdi + 0]
    mov rbp, [rdi + 8]
    mov rsp, [rdi + 16]
    mov r12, [rdi + 24]
    mov r13, [rdi + 32]
    mov r14, [rdi + 40]
    mov r15, [rdi + 48]

    mov rax, rsi
    test rax, rax
    jne .ret
    mov rax, 1

.ret:
    mov rdx, [rdi +56]
    jmp rdx
