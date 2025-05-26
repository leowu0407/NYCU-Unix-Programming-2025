#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <stddef.h>


typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t);


static syscall_hook_fn_t original_syscall = NULL;

// handle escaped string content for read/write
static void log_escaped_string(FILE *stream, const char *buf, size_t len_to_process, size_t total_original_len) {
    size_t limit = (len_to_process < 32) ? len_to_process : 32;
    fputc('"', stream);
    for (size_t i = 0; i < limit; ++i) {
        unsigned char c = buf[i];
        switch (c) {
            case '\n': fprintf(stream, "\\n"); break;
            case '\r': fprintf(stream, "\\r"); break;
            case '\t': fprintf(stream, "\\t"); break;
            // Note: Requirements don't explicitly ask to escape ", \, etc. within the string.
            //       If needed, add more cases here.
            default:
                // Check if printable ASCII (excluding \t, \n, \r handled above)
                if (c >= 32 && c <= 126) {
                    fputc(c, stream);
                } 
                else {
                    // Non-printable, format as \xhh
                    fprintf(stream, "\\x%02x", c);
                }
                break;
        }
    }
    fputc('"', stream);
    if (total_original_len > 128) {
        fprintf(stream, "...");
    }
}

// format socket address for connect
static void format_sockaddr(char *buffer, size_t buffer_size, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr == NULL || buffer_size == 0) {
        snprintf(buffer, buffer_size, "NULL_ADDR");
        return;
    }

    switch (addr->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN);
            snprintf(buffer, buffer_size, "%s:%d", ip_str, ntohs(addr_in->sin_port));
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
            snprintf(buffer, buffer_size, "%s:%d", ip_str, ntohs(addr_in6->sin6_port));
            break;
        }
        case AF_UNIX: {
            struct sockaddr_un *addr_un = (struct sockaddr_un *)addr;
            size_t path_offset = offsetof(struct sockaddr_un, sun_path);

            if (addrlen <= path_offset) {
                 snprintf(buffer, buffer_size, "UNIX:INVALID_PATH_LEN");
                 break;
            }
            size_t max_path_len = addrlen - path_offset;
            size_t prefix_len = strlen("UNIX:");
            size_t buffer_avail = buffer_size - prefix_len - 1; // -1 for null terminator

            size_t copy_len = (max_path_len < buffer_avail) ? max_path_len : buffer_avail;

            strcpy(buffer, "UNIX:");
            // Check for abstract socket namespace (starts with null byte)
            if (addr_un->sun_path[0] == '\0' && max_path_len > 1) {
                strcat(buffer, "@"); // Use '@' convention for abstract sockets
                memcpy(buffer + prefix_len, addr_un->sun_path, copy_len);
                buffer[prefix_len + copy_len] = '\0'; // Ensure null termination

            } 
            else {
                memcpy(buffer + prefix_len, addr_un->sun_path, copy_len);
                buffer[prefix_len + copy_len] = '\0'; // Ensure null termination
            }
            break;
        }
        default:
            snprintf(buffer, buffer_size, "UNKNOWN_FAMILY_%d", addr->sa_family);
            break;
    }
}


// The hook function that intercepts system calls
static int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx,
                               int64_t r10, int64_t r8, int64_t r9,
                               int64_t rax) {

    //fprintf(stderr, "Intercepted syscall: %ld\n", rax);

    if (rax == SYS_execve) {
        const char *filename = (const char *)rdi;
        void *argv_ptr = (void *)rsi;
        void *envp_ptr = (void *)rdx;
        fprintf(stderr, "[logger] execve(\"%s\", %p, %p)\n", filename, argv_ptr, envp_ptr);
        // has return value only when execve fail
    }

    int64_t return_value = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);

    switch (rax) {
        case SYS_openat: {
            int dirfd = (int)rdi;
            const char *pathname = (const char *)rsi;
            int flags = (int)rdx;
            mode_t mode = (mode_t)r10; // mode is 4th arg (r10) for openat

            fprintf(stderr, "[logger] openat(");
            if (dirfd == AT_FDCWD) {
                fprintf(stderr, "AT_FDCWD");
            } 
            else {
                fprintf(stderr, "%d", dirfd);
            }

            fprintf(stderr, ", \"%s\", 0x%x, %#o) = %ld\n", pathname, flags, mode, return_value);
            break;
        }

        case SYS_read: {
            int fd = (int)rdi;
            void *buf = (void *)rsi;
            size_t count = (size_t)rdx;

            fprintf(stderr, "[logger] read(%d, ", fd);
            // Only process buffer content if read succeeded (return_value > 0)
            if (return_value > 0) {
                log_escaped_string(stderr, (const char *)buf, (size_t)return_value, count);
            } 
            else {
                 fputc('"', stderr); // Print empty quotes if read failed or returned 0
                 fputc('"', stderr);
            }
            fprintf(stderr, ", %zu) = %ld\n", count, return_value);
            break;
        }

        case SYS_write: {
            int fd = (int)rdi;
            const void *buf = (const void *)rsi;
            size_t count = (size_t)rdx;

            fprintf(stderr, "[logger] write(%d, ", fd);
            log_escaped_string(stderr, (const char *)buf, count, count);
            fprintf(stderr, ", %zu) = %ld\n", count, return_value);
            break;
        }

        case SYS_connect: {
            int sockfd = (int)rdi;
            const struct sockaddr *addr = (const struct sockaddr *)rsi;
            socklen_t addrlen = (socklen_t)rdx;
            char addr_str_buffer[INET6_ADDRSTRLEN + sizeof("UNIX:") + 256]; // Buffer for formatted address

            format_sockaddr(addr_str_buffer, sizeof(addr_str_buffer), addr, addrlen);

            fprintf(stderr, "[logger] connect(%d, \"%s\", %u) = %ld\n", sockfd, addr_str_buffer, addrlen, return_value);
            break;
        }

    }

    return return_value;
}

void __hook_init(const syscall_hook_fn_t trigger_syscall,
                 syscall_hook_fn_t *hooked_syscall) {

    original_syscall = trigger_syscall;
    *hooked_syscall = syscall_hook_fn;
}

