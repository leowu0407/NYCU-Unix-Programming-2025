// sdb.cpp
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <map>
#include <fstream>
#include <cstring>    // For strsignal, strlen, etc.
#include <cstdlib>    // For realpath, exit, stoll, stoi
#include <limits.h>   // For PATH_MAX <--- Added

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h> // For user_regs_struct
#include <unistd.h>   // For fork, exec, readlink, getpid etc.
#include <elf.h>
#include <capstone/capstone.h>
#include <fcntl.h>    // For open

// Helper to split string by delimiter
std::vector<std::string> split_string(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// Convert hex string to unsigned long long
unsigned long long hex_to_ullong(std::string hex_str) { // Changed return type and name
    if (hex_str.rfind("0x", 0) == 0 || hex_str.rfind("0X", 0) == 0) {
        hex_str = hex_str.substr(2);
    }
    if (hex_str.empty()) { // Good to add an explicit check
        throw std::invalid_argument("hex_to_ullong: input string is empty after 0x removal");
    }
    return std::stoull(hex_str, nullptr, 16); // Changed to stoull
}

struct Breakpoint {
    int id;
    unsigned long long address;
    unsigned char original_byte; // Byte replaced by 0xCC
    bool enabled;

    Breakpoint() : id(-1), address(0), original_byte(0), enabled(false) {}

    Breakpoint(int i, unsigned long long addr, unsigned char orig_byte)
        : id(i), address(addr), original_byte(orig_byte), enabled(true) {}
};

class Debugger {
public:
    Debugger() : child_pid_(-1), program_loaded_(false), entry_point_(0), base_address_(0),
                 next_breakpoint_id_(0), capstone_handle_(0), in_syscall_entry_(false) {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle_) != CS_ERR_OK) {
            std::cerr << "** Capstone initialization failed." << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    ~Debugger() {
        if (capstone_handle_ != 0) {
            cs_close(&capstone_handle_);
        }
        if (child_pid_ > 0) {
            kill_program(); 
        }
    }

    void run(const std::string& program_path = "") {
        if (!program_path.empty()) {
            load_program_internal(program_path);
        }

        std::string line;
        while (true) {
            std::cout << "(sdb) " << std::flush;
            if (!std::getline(std::cin, line)) {
                if (program_loaded_ && child_pid_ > 0) { // Handle EOF by trying to clean up
                    kill_program();
                }
                break; 
            }

            std::vector<std::string> args = split_string(line, ' ');
            if (args.empty() || args[0].empty()) {
                continue;
            }

            const std::string& command = args[0];

            if (command == "load") {
                if (args.size() < 2) {
                    std::cerr << "** Usage: load [path to program]" << std::endl;
                } else {
                    load_program_internal(args[1]);
                }
            } else if (command == "exit" || command == "quit" || command == "q") {
                kill_program();
                break;
            }
            else if (!program_loaded_) {
                if (command == "si" || command == "cont" || command == "info" ||
                    command == "break" || command == "breakrva" || command == "delete" ||
                    command == "patch" || command == "syscall") {
                    std::cout << "** please load a program first." << std::endl;
                } else {
                    std::cout << "** Unknown command: " << command << std::endl;
                }
            } else if (command == "si") {
                step_instruction();
            } else if (command == "cont") {
                continue_execution();
            } else if (command == "info") {
                if (args.size() > 1 && args[1] == "reg") {
                    print_registers();
                } else if (args.size() > 1 && args[1] == "break") {
                    info_breakpoints();
                } else {
                    std::cout << "** Usage: info reg | info break" << std::endl;
                }
            } else if (command == "break") {
                if (args.size() < 2) {
                    std::cout << "** Usage: break [hex address]" << std::endl;
                } else {
                    set_breakpoint(args[1]);
                }
            } else if (command == "breakrva") {
                if (args.size() < 2) {
                     std::cout << "** Usage: breakrva [hex offset]" << std::endl;
                } else {
                    set_breakpoint_rva(args[1]);
                }
            } else if (command == "delete") {
                if (args.size() < 2) {
                    std::cout << "** Usage: delete [id]" << std::endl;
                } else {
                    try {
                        delete_breakpoint(std::stoi(args[1]));
                    } catch (const std::exception& e) {
                        std::cout << "** Invalid breakpoint id format." << std::endl;
                    }
                }
            } else if (command == "patch") {
                 if (args.size() < 3) {
                    std::cout << "** Usage: patch [hex address] [hex string]" << std::endl;
                } else {
                    patch_memory(args[1], args[2]);
                }
            } else if (command == "syscall") {
                handle_syscall_command();
            }
            else {
                std::cout << "** Unknown command: " << command << std::endl;
            }
        }
    }

private:
    pid_t child_pid_;
    bool program_loaded_;
    std::string current_program_path_;
    unsigned long long entry_point_; 
    unsigned long long base_address_;  
    struct user_regs_struct regs_;
    std::map<unsigned long long, Breakpoint> breakpoints_map_; 
    std::map<int, unsigned long long> breakpoint_id_to_addr_; 
    int next_breakpoint_id_;
    csh capstone_handle_;
    std::vector<std::pair<unsigned long long, unsigned long long>> executable_regions_;
    bool in_syscall_entry_; 

    void kill_program() {
        if (child_pid_ > 0) {
            // Attempt to restore original bytes at breakpoints
            for (auto it = breakpoints_map_.begin(); it != breakpoints_map_.end(); ) {
                if (it->second.enabled) {
                    // Check current byte in memory; if it's 0xCC, restore original.
                    // This is best-effort as process might be unresponsive.
                    unsigned char current_mem_byte = read_memory_byte(it->first);
                    if (current_mem_byte == 0xCC) { // Check if our 0xCC is still there
                         write_memory_byte(it->first, it->second.original_byte);
                    }
                }
                it = breakpoints_map_.erase(it); // Erase while iterating safely
            }
            breakpoint_id_to_addr_.clear();

            if (ptrace(PTRACE_DETACH, child_pid_, nullptr, nullptr) < 0) {
                // If detach fails, process might already be dead or in a weird state
                // perror("ptrace PTRACE_DETACH");
            }
            // Send SIGKILL as a last resort if it's still alive
            if (kill(child_pid_, 0) == 0) { // Check if process exists
                 kill(child_pid_, SIGKILL);
            }
            waitpid(child_pid_, nullptr, 0); // Reap the child
            
            child_pid_ = -1; // Reset PID
            program_loaded_ = false;
            executable_regions_.clear();
            next_breakpoint_id_ = 0;
            // entry_point_ = 0; // Reset these too
            // base_address_ = 0;
        }
    }

    unsigned long long get_elf_entry_offset(const std::string& path) {
        int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) {
            std::cerr << "** Failed to open ELF file: " << path << " (get_elf_entry_offset)" << std::endl;
            return 0;
        }
        Elf64_Ehdr ehdr;
        if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
            std::cerr << "** Failed to read ELF header from: " << path << std::endl;
            close(fd);
            return 0;
        }
        close(fd);
        if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
            ehdr.e_ident[EI_MAG2] != ELFMAG2 || ehdr.e_ident[EI_MAG3] != ELFMAG3) {
            std::cerr << "** Not an ELF file: " << path << std::endl;
            return 0;
        }
        return ehdr.e_entry;
    }

    void parse_proc_maps() {
        executable_regions_.clear();
        base_address_ = 0; // Reset before parsing
        if (child_pid_ <= 0) return;

        std::string maps_path = "/proc/" + std::to_string(child_pid_) + "/maps";
        std::ifstream maps_file(maps_path);
        if (!maps_file.is_open()){
            //std::cerr << "** Could not open " << maps_path << std::endl;
            return;
        }
        std::string line;
        
        std::string proc_exe_path;
        char exe_path_buf[PATH_MAX]; // PATH_MAX from limits.h
        std::string link_path = "/proc/" + std::to_string(child_pid_) + "/exe";
        ssize_t len = readlink(link_path.c_str(), exe_path_buf, sizeof(exe_path_buf)-1);
        if (len != -1) {
            exe_path_buf[len] = '\0';
            proc_exe_path = std::string(exe_path_buf);
        }

        unsigned long long potential_base_address = -1ULL; // For PIE without direct name match

        while (std::getline(maps_file, line)) {
            std::stringstream ss(line);
            std::string addr_range, perms, offset_str, dev, inode_str, pathname_from_map;
            ss >> addr_range >> perms >> offset_str >> dev >> inode_str;
            // Handle cases where pathname might be empty or have spaces (though unlikely for main exe)
            std::getline(ss, pathname_from_map); 
            if (!pathname_from_map.empty() && pathname_from_map.front() == ' ') { // .front() is C++11
                pathname_from_map.erase(0, pathname_from_map.find_first_not_of(" ")); // 更健壮的 trim 前导空格
            }
            if (!pathname_from_map.empty() && pathname_from_map[0] == ' ') { // trim leading space
                 pathname_from_map = pathname_from_map.substr(1);
            }


            size_t hyphen_pos = addr_range.find('-');
            if (hyphen_pos == std::string::npos) continue;
            unsigned long long start_addr_map, end_addr_map, map_offset;
            try {
                start_addr_map = hex_to_ullong(addr_range.substr(0, hyphen_pos));
                end_addr_map = hex_to_ullong(addr_range.substr(hyphen_pos + 1));
                map_offset = hex_to_ullong(offset_str);
            } catch (const std::exception& e) {
                // std::cerr << "** Warning: Failed to parse map line: " << line << " (" << e.what() << ")" << std::endl;
                continue; 
            }
            
            bool path_matches = false;
            if (!pathname_from_map.empty()){
                if (pathname_from_map == current_program_path_) path_matches = true;
                else if (!proc_exe_path.empty() && pathname_from_map == proc_exe_path) path_matches = true;
            }

            if (path_matches) {
            // 关键逻辑：寻找文件偏移量为0的段，并取其最低的起始虚拟地址
                if (map_offset == 0) {
                    if (potential_base_address == -1ULL || start_addr_map < potential_base_address) {
                        potential_base_address = start_addr_map; // 这是一个候选的基地址
                    }
                }
            }
            // 仍然需要填充可执行区域列表
            if (perms.find('x') != std::string::npos) { 
                executable_regions_.push_back({start_addr_map, end_addr_map});
            }
        }
        maps_file.close();

        if (potential_base_address != -1ULL) {
            base_address_ = potential_base_address;
        }
    }

    bool is_address_in_executable_region(unsigned long long addr) {
        if (executable_regions_.empty() && child_pid_ > 0 && program_loaded_) {
            // This might happen if maps weren't parsed or cleared unexpectedly.
            // Attempt a re-parse, but this is a fallback.
            // parse_proc_maps();
        }
        for (const auto& region : executable_regions_) {
            if (addr >= region.first && addr < region.second) {
                return true;
            }
        }
        return false;
    }


    void load_program_internal(const std::string& program_path) {
        if (program_loaded_) {
            kill_program(); 
        }
        
        // Reset state for new program
        entry_point_ = 0;
        base_address_ = 0;
        executable_regions_.clear();
        breakpoints_map_.clear();
        breakpoint_id_to_addr_.clear();
        next_breakpoint_id_ = 0;


        char abs_program_path[PATH_MAX];
        if (realpath(program_path.c_str(), abs_program_path) == NULL) {
            std::cerr << "** Failed to resolve absolute path for: " << program_path << " (errno: " << errno << ")" << std::endl;
            //perror("** realpath failed");
            current_program_path_ = program_path; // Use as is, exec might still find it in PATH
        } else {
            current_program_path_ = abs_program_path;
        }
        
        child_pid_ = fork();

        if (child_pid_ == 0) { 
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
                perror("** ptrace(TRACEME) failed");
                _exit(EXIT_FAILURE); // Use _exit in child after fork to avoid stdio buffer issues
            }
            execl(current_program_path_.c_str(), current_program_path_.c_str(), (char*)nullptr);
            perror("** execl failed"); 
            _exit(EXIT_FAILURE);
        } else if (child_pid_ > 0) { 
            int status;
            waitpid(child_pid_, &status, 0); 
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                 std::cerr << "** Program '" << current_program_path_ << "' terminated unexpectedly during load." << std::endl;
                 child_pid_ = -1; // Mark child as gone
                 return;
            }
            
            program_loaded_ = true; // Tentatively set loaded to allow helper functions
            parse_proc_maps(); 

            unsigned long long elf_entry_offset = get_elf_entry_offset(current_program_path_); 

            if (elf_entry_offset == 0) {
                 std::cerr << "** Failed to get ELF entry point offset from " << current_program_path_ << "." << std::endl;
                 if (base_address_ == 0 && program_path.find("hola") == std::string::npos) { // hola is PIE and expects this, others might not
                    // Don't kill if base_address can still be used as entry for non-PIE
                 } else if (base_address_ == 0) { // If no base and no offset, it's bad
                    kill_program(); // This will set program_loaded_ = false
                    return;
                 }
            }
            
            int fd_elf_type = open(current_program_path_.c_str(), O_RDONLY);
            Elf64_Ehdr ehdr_type_check;
            bool is_pie_or_dyn = false;
            if (fd_elf_type >= 0) {
                if (read(fd_elf_type, &ehdr_type_check, sizeof(ehdr_type_check)) == sizeof(ehdr_type_check)) {
                    if (ehdr_type_check.e_type == ET_DYN) {
                        is_pie_or_dyn = true;
                    }
                }
                close(fd_elf_type);
            }

            if (is_pie_or_dyn) { // Typically PIE or shared library
                 if (base_address_ == 0) {
                    std::cerr << "** PIE/Dynamic executable but base address could not be determined for " << current_program_path_ << std::endl;
                    kill_program(); return;
                 }
                 entry_point_ = base_address_ + elf_entry_offset;
            } else { // ET_EXEC (non-PIE)
                 entry_point_ = elf_entry_offset;
                 if (base_address_ == 0 && entry_point_ != 0) { // If maps didn't find base for non-PIE, derive it
                    // This is a heuristic. For non-PIE, base_address usually matches the lowest PT_LOAD segment's p_vaddr.
                    // The e_entry is often within this first loadable segment.
                    // If e_entry is 0x401000, and offset is 0x1000, base would be 0x400000.
                    // For simplicity, if base_address_ is 0 for non-PIE, assume no RVA calculation needed for breakpoints.
                    // Let's set base_address_ to where the .text segment typically starts for non-PIE if we need it for breakrva.
                    // A common non-PIE base is where e_entry points, minus its own offset within .text.
                    // For now, if base_address_ is 0, 'breakrva' will be problematic for non-PIE.
                    // We can assume base_address for non-PIE is effectively the load address which might be 0 in some views,
                    // and entry_point_ is absolute.
                    // Let's try to set a meaningful base_address_ if it's ET_EXEC
                     base_address_ = entry_point_ - elf_entry_offset; // This makes offset 0 point to image base
                 } else if (base_address_ != 0 && (entry_point_ < base_address_ || entry_point_ > base_address_ + 0x10000000)) {
                     // If base_address from maps seems inconsistent with non-PIE entry_point (e.g. linker base vs program base)
                     // Trust the non-PIE entry_point as absolute.
                 }
            }
            if (entry_point_ == 0 && base_address_ != 0 && elf_entry_offset == 0 && is_pie_or_dyn) {
                // Case: PIE with entry point offset 0, so entry is just base_address
                entry_point_ = base_address_;
            }


            if (entry_point_ == 0) {
                std::cerr << "** Could not determine entry point for " << current_program_path_ << std::endl;
                kill_program(); return;
            }

            get_registers(); 

            if (regs_.rip != entry_point_) {
                unsigned char original_byte_at_entry = read_memory_byte(entry_point_);
                if (errno != 0 && original_byte_at_entry == 0) { 
                    std::cerr << "** Failed to read memory at calculated entry point 0x" << std::hex << entry_point_ << std::dec << ". Dynamic linking issue or wrong address." << std::endl;
                    kill_program(); return;
                }
                write_memory_byte(entry_point_, 0xCC); 

                ptrace(PTRACE_CONT, child_pid_, nullptr, nullptr);
                waitpid(child_pid_, &status, 0);

                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                    write_memory_byte(entry_point_, original_byte_at_entry); 
                    get_registers();
                    if (regs_.rip == entry_point_ + 1) { 
                        regs_.rip--; 
                        set_registers();
                    } else if (regs_.rip != entry_point_){
                         std::cerr << "** Warning: After temp BP, RIP is 0x" << std::hex << regs_.rip 
                                   << ", expected 0x" << entry_point_ << std::dec << std::endl;
                        // Potentially adjust RIP if it makes sense, or accept the stop.
                        // For now, we assume it stopped *at* the entry point after restoring byte.
                        if (regs_.rip > entry_point_ + 16 || regs_.rip < entry_point_ -16) { // If too far off
                             // kill_program(); return; // Drastic
                        }
                    }
                } else {
                    std::cerr << "** Error: Did not hit temporary breakpoint at program entry 0x" << std::hex << entry_point_ << std::dec << "." << std::endl;
                     if (WIFEXITED(status)) std::cerr << "** Program exited during setup." << std::endl;
                     else if (WIFSIGNALED(status)) std::cerr << "** Program signalled during setup: " << strsignal(WTERMSIG(status)) << std::endl;
                     else if (WIFSTOPPED(status)) std::cerr << "** Program stopped by signal: " << strsignal(WSTOPSIG(status)) << std::endl;
                    kill_program(); return;
                }
            }

            std::cout << std::hex << "** program '" << program_path << "' loaded. entry point: 0x" << entry_point_ << "." << std::dec << std::endl;
            
            // Re-parse maps after dynamic linker might have run and settled memory layout,
            // especially to ensure executable_regions_ are accurate.
            parse_proc_maps(); 
            disassemble_instructions(5);

        } else {
            perror("** fork failed");
             program_loaded_ = false; // Ensure it's false if fork fails
        }
    }

    void get_registers() {
        if (child_pid_ <= 0 || !program_loaded_) return;
        if (ptrace(PTRACE_GETREGS, child_pid_, nullptr, &regs_) < 0) {
            // perror("** ptrace(GETREGS) failed"); // Can be too verbose if child exited
        }
    }

    void set_registers() {
        if (child_pid_ <= 0 || !program_loaded_) return;
        if (ptrace(PTRACE_SETREGS, child_pid_, nullptr, &regs_) < 0) {
            // perror("** ptrace(SETREGS) failed");
        }
    }

    unsigned char read_memory_byte(unsigned long long addr) {
        if (child_pid_ <= 0 || !program_loaded_) return 0; 
        errno = 0; 
        long data = ptrace(PTRACE_PEEKTEXT, child_pid_, addr, nullptr);
        if (data == -1 && errno != 0) { 
            // perror("** ptrace(PEEKTEXT) failed to read byte"); 
            return 0; 
        }
        return (unsigned char)(data & 0xFF);
    }

    void write_memory_byte(unsigned long long addr, unsigned char byte) {
        if (child_pid_ <= 0 || !program_loaded_) return;
        errno = 0;
        long data = ptrace(PTRACE_PEEKTEXT, child_pid_, addr, nullptr);
         if (data == -1 && errno != 0) {
            // perror("** ptrace(PEEKTEXT) failed before write");
            return;
        }
        long new_data = (data & ~0xFFL) | byte; 
        if (ptrace(PTRACE_POKETEXT, child_pid_, addr, new_data) < 0) {
            // perror("** ptrace(POKETEXT) failed to write byte");
        }
    }


    void disassemble_instructions(int count) {
        if (!program_loaded_ || child_pid_ <= 0) return;
        get_registers(); 
        unsigned long long current_rip = regs_.rip;

        const int MAX_INSTR_BYTES_PER_INS = 15; 
        unsigned char buffer[MAX_INSTR_BYTES_PER_INS * count + MAX_INSTR_BYTES_PER_INS]; // Extra for safety
        size_t total_bytes_read = 0;
        
        // Try to read enough bytes for 'count' instructions
        for (int i = 0; i < count && total_bytes_read < sizeof(buffer) - MAX_INSTR_BYTES_PER_INS; ) {
            unsigned long long instr_addr_to_read = current_rip + total_bytes_read;
            if (!is_address_in_executable_region(instr_addr_to_read)){
                 break; // Stop if current address is out of bounds
            }

            cs_insn *temp_insn;
            unsigned char single_instr_buffer[MAX_INSTR_BYTES_PER_INS];
            size_t single_instr_bytes_count = 0;

            for(int k=0; k<MAX_INSTR_BYTES_PER_INS; ++k) {
                unsigned long long byte_addr = instr_addr_to_read + k;
                 if (!is_address_in_executable_region(byte_addr)) break;
                auto bp_it = breakpoints_map_.find(byte_addr);
                if (bp_it != breakpoints_map_.end() && bp_it->second.enabled) {
                    single_instr_buffer[k] = bp_it->second.original_byte;
                } else {
                    single_instr_buffer[k] = read_memory_byte(byte_addr);
                    if (errno != 0 && single_instr_buffer[k] == 0) { // Read failed
                        break; // Stop reading for this instruction
                    }
                }
                single_instr_bytes_count++;
            }
            if(single_instr_bytes_count == 0) break; // Cannot read even one byte

            size_t disas_count = cs_disasm(capstone_handle_, single_instr_buffer, single_instr_bytes_count, instr_addr_to_read, 1, &temp_insn);
            if (disas_count > 0) {
                // Copy the valid instruction bytes to main buffer
                if (total_bytes_read + temp_insn[0].size <= sizeof(buffer)) {
                    memcpy(buffer + total_bytes_read, temp_insn[0].bytes, temp_insn[0].size);
                    total_bytes_read += temp_insn[0].size;
                    i++; // Successfully read one instruction
                } else {
                     cs_free(temp_insn, disas_count);
                     break; // Not enough space in main buffer
                }
                cs_free(temp_insn, disas_count);
            } else {
                // Could not disassemble, maybe not enough bytes or invalid sequence.
                // Try to copy at least one byte if we read any, to let main disassembler try.
                if (single_instr_bytes_count > 0 && total_bytes_read < sizeof(buffer)) {
                    buffer[total_bytes_read++] = single_instr_buffer[0];
                }
                break; // Stop trying to read more instructions this way
            }
        }


        if (total_bytes_read == 0 && count > 0) {
             if (!is_address_in_executable_region(current_rip)) {
                std::cout << "** the address is out of the range of the executable region." << std::endl;
            } else {
                // std::cout << "** Could not read any bytes for disassembly at 0x" << std::hex << current_rip << std::dec << std::endl;
            }
            return;
        }

        cs_insn *insn_array; // Changed variable name
        size_t num_insns_disassembled = cs_disasm(capstone_handle_, buffer, total_bytes_read, current_rip, count, &insn_array);

        if (num_insns_disassembled > 0) {
            for (size_t i = 0; i < num_insns_disassembled; ++i) {
                if (!is_address_in_executable_region(insn_array[i].address)) {
                    std::cout << "** the address is out of the range of the executable region." << std::endl;
                    break; 
                }
                std::cout << "      " << std::hex << insn_array[i].address << ": ";
                std::string bytes_str;
                for (size_t j = 0; j < insn_array[i].size; ++j) {
                    bytes_str += (j == 0 ? "" : " ") + (std::stringstream() << std::setw(2) << std::setfill('0') << std::hex << (int)insn_array[i].bytes[j]).str();
                }
                std::cout << std::left << std::setw(30) << bytes_str; 
                std::cout << std::left << std::setw(10) << insn_array[i].mnemonic; 
                std::cout << insn_array[i].op_str << std::endl;
            }
            cs_free(insn_array, num_insns_disassembled);
            
            if (num_insns_disassembled < static_cast<size_t>(count)) {
                unsigned long long next_addr_check = current_rip;
                 cs_insn *last_disas_insn;
                 size_t last_disas_count = cs_disasm(capstone_handle_, buffer, total_bytes_read, current_rip, num_insns_disassembled, &last_disas_insn);

                if (last_disas_count > 0) { 
                    next_addr_check = last_disas_insn[last_disas_count-1].address + last_disas_insn[last_disas_count-1].size;
                    cs_free(last_disas_insn, last_disas_count);
                } else { 
                    next_addr_check = current_rip + total_bytes_read; 
                }

                if (!is_address_in_executable_region(next_addr_check)) {
                    std::cout << "** the address is out of the range of the executable region." << std::endl;
                }
            }
        } else { 
            if (!is_address_in_executable_region(current_rip)) {
                 std::cout << "** the address is out of the range of the executable region." << std::endl;
            } else if (total_bytes_read > 0) { 
                std::cout << "** Disassembly failed at 0x" << std::hex << current_rip << std::dec << ". Read " << total_bytes_read << " byte(s)." << std::endl;
            }
        }
        std::cout << std::dec; 
    }

    void handle_wait_status(int status, bool disassemble = true) {
        if (child_pid_ <= 0 && !(WIFEXITED(status) || WIFSIGNALED(status))) { 
            return;
        }

        if (WIFEXITED(status)) {
            std::cout << "** the target program terminated." << std::endl;
            program_loaded_ = false;
            child_pid_ = -1; 
            breakpoints_map_.clear();
            breakpoint_id_to_addr_.clear();
            executable_regions_.clear();
            return; // Return early, no more operations on child
        } else if (WIFSIGNALED(status)) {
            std::cout << "** the target program terminated by signal " << strsignal(WTERMSIG(status)) << "." << std::endl;
            program_loaded_ = false;
            child_pid_ = -1;
            breakpoints_map_.clear();
            breakpoint_id_to_addr_.clear();
            executable_regions_.clear();
            return; // Return early
        }
        else if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            get_registers(); 

            siginfo_t siginfo; 
            if (ptrace(PTRACE_GETSIGINFO, child_pid_, nullptr, &siginfo) != 0) {
                //perror("PTRACE_GETSIGINFO"); 
            }

            if (sig == SIGTRAP) {
                unsigned long long bp_check_addr = regs_.rip - 1; 
                auto bp_it = breakpoints_map_.find(bp_check_addr);

                if (bp_it != breakpoints_map_.end() && bp_it->second.enabled && siginfo.si_code == TRAP_BRKPT) {
                    // Check if this breakpoint is the one we expected to hit for 'syscall' or 'cont' commands.
                    // If current_command_ is "si", this is a natural hit.
                    // bool is_expected_bp_for_cont_syscall = (current_command_ == "cont" || current_command_ == "syscall");
                    
                    // The spec says for break: "If the user resumes the program with si , cont or syscall, 
                    // the program should not stop at the same breakpoint twice."
                    // And for break at current RIP: "do not output ** hit a breakpoint at [hex address]."
                    // This implies if RIP was already at BP when command was issued, don't show "hit".
                    // My logic for cont/syscall already single-steps over current BP then continues/syscalls.
                    // So this 'hit' message is for BPs encountered *during* that cont/syscall.

                    std::cout << std::hex << "** hit a breakpoint at 0x" << bp_check_addr << "." << std::dec << std::endl;
                    write_memory_byte(bp_check_addr, bp_it->second.original_byte);
                    regs_.rip = bp_check_addr;
                    set_registers();
                // Fix for pointer/integer comparison
                } else if (current_command_ == "syscall" && 
                           (regs_.rip - 2) == reinterpret_cast<unsigned long long>(siginfo.si_addr) &&
                           siginfo.si_code != TRAP_BRKPT ) { // Ensure it's not a breakpoint on syscall
                     if (in_syscall_entry_) {
                        long syscall_num = regs_.orig_rax;
                        std::cout << std::hex << "** enter a syscall(" << syscall_num << ") at 0x" << (regs_.rip - 2) << "." << std::dec << std::endl; 
                        in_syscall_entry_ = false; 
                     } else { 
                        long syscall_num_on_exit = regs_.orig_rax; 
                        long ret_val = regs_.rax;       
                        std::cout << std::hex << "** leave a syscall(" << syscall_num_on_exit << ") = " << ret_val << " at 0x" << (regs_.rip - 2) << "." << std::dec << std::endl;
                     }
                } else { 
                    // Generic SIGTRAP (e.g. from PTRACE_SINGLESTEP) or other non-BP, non-syscall SIGTRAP.
                    // No specific message needed by spec unless it's a new BP hit.
                }
            } else { 
                std::cout << "** Child stopped by signal " << strsignal(sig) << " (SIG=" << sig << ")" << std::endl;
                if (sig == SIGSEGV || sig == SIGILL || sig == SIGBUS || sig == SIGFPE) { 
                    // These are often fatal. The program might exit soon after.
                    // We don't mark program_loaded_ false here yet, wait for WIFEXITED/WIFSIGNALED.
                }
            }

            if (program_loaded_ && disassemble && child_pid_ > 0) { // Check child_pid_ again in case it was reset
                disassemble_instructions(5);
            }
        }
    }
    std::string current_command_; 

    void step_instruction() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        current_command_ = "si";
        in_syscall_entry_ = false; 
        get_registers();
        unsigned long long rip_before_step = regs_.rip;

        auto bp_it = breakpoints_map_.find(rip_before_step);
        bool was_on_breakpoint = (bp_it != breakpoints_map_.end() && bp_it->second.enabled);
        
        // If we are on a breakpoint, original byte is already restored by handle_wait_status.
        // So, PTRACE_SINGLESTEP will execute the original instruction.

        if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) {
            //perror("** ptrace(SINGLESTEP) failed");
            return;
        }
        int status;
        waitpid(child_pid_, &status, 0);

        if (was_on_breakpoint) {
            // After stepping the original instruction, restore the 0xCC for the breakpoint.
            write_memory_byte(rip_before_step, 0xCC);
        }
        handle_wait_status(status);
    }

    void continue_execution() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        current_command_ = "cont";
        in_syscall_entry_ = false;
        get_registers();
        unsigned long long rip_before_op = regs_.rip;

        auto bp_it = breakpoints_map_.find(rip_before_op);
        if (bp_it != breakpoints_map_.end() && bp_it->second.enabled ) {
            // Original byte is restored at rip_before_op. Step over it.
            if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) {
                return;
            }
            int temp_status;
            waitpid(child_pid_, &temp_status, 0);

            write_memory_byte(rip_before_op, 0xCC); // Re-enable the breakpoint

            if (WIFEXITED(temp_status) || WIFSIGNALED(temp_status)) {
                handle_wait_status(temp_status); 
                return; 
            }
            // If single step stopped for another non-fatal reason (e.g., another BP or different signal)
            // handle_wait_status will be called below if we don't PTRACE_CONT.
            // For 'cont', after stepping over the initial BP, we *must* continue.
            // So, we don't call handle_wait_status here for the intermediate step unless it's fatal.
            // The main PTRACE_CONT below will handle the next stop.
        }

        if (ptrace(PTRACE_CONT, child_pid_, nullptr, nullptr) < 0) {
            return;
        }
        int status;
        waitpid(child_pid_, &status, 0);
        handle_wait_status(status);
    }


    void handle_syscall_command() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        current_command_ = "syscall";
        // in_syscall_entry_ will be set true just before PTRACE_SYSCALL
        
        get_registers();
        unsigned long long rip_before_op = regs_.rip;
        
        auto bp_it = breakpoints_map_.find(rip_before_op);
        if (bp_it != breakpoints_map_.end() && bp_it->second.enabled) {
            // On a breakpoint, step over it. Original byte is already restored.
            if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) {
                return;
            }
            int temp_status;
            waitpid(child_pid_, &temp_status, 0);
            write_memory_byte(rip_before_op, 0xCC); // Re-enable breakpoint

            if (WIFEXITED(temp_status) || WIFSIGNALED(temp_status) ) {
                handle_wait_status(temp_status); 
                return;
            }
            
            // Now, check if this single step landed on another breakpoint or a syscall instruction
            // If it landed on a breakpoint, the spec says: "If it hits a breakpoint, output ** hit a breakpoint at [hex address]."
            // and then it should stop and show disassembly.
            if (WIFSTOPPED(temp_status) && WSTOPSIG(temp_status) == SIGTRAP) {
                get_registers(); // Get current RIP after the step
                siginfo_t siginfo_step;
                ptrace(PTRACE_GETSIGINFO, child_pid_, nullptr, &siginfo_step);
                unsigned long long stepped_to_bp_check_addr = regs_.rip - 1;
                auto next_bp_it = breakpoints_map_.find(stepped_to_bp_check_addr);

                if (next_bp_it != breakpoints_map_.end() && next_bp_it->second.enabled && siginfo_step.si_code == TRAP_BRKPT) {
                    // We single-stepped from one breakpoint into another.
                    handle_wait_status(temp_status); // This will print "hit a breakpoint"
                    return; // Stop, user needs to issue another command. Do not proceed to PTRACE_SYSCALL.
                 }
            } else if (WIFSTOPPED(temp_status)) { // Stopped by other signal
                 handle_wait_status(temp_status); // Handle the other signal
                 return; // Do not proceed.
            }
            // If single step didn't exit and didn't hit another breakpoint, then proceed with PTRACE_SYSCALL
        }
        
        in_syscall_entry_ = true; 
        if (ptrace(PTRACE_SYSCALL, child_pid_, nullptr, nullptr) < 0) {
            in_syscall_entry_ = false; // Reset if ptrace fails
            return;
        }
        int status;
        waitpid(child_pid_, &status, 0);
        // If PTRACE_SYSCALL itself fails to make the child stop (e.g., child died before),
        // in_syscall_entry_ might remain true. handle_wait_status should clear it if child exits.
        if(WIFEXITED(status) || WIFSIGNALED(status)) {
            in_syscall_entry_ = false; // Clear if child exited
        }
        handle_wait_status(status);
    }


    void print_registers() {
        if (!program_loaded_ || child_pid_ <=0) {
             std::cout << "** No program loaded or child not running." << std::endl;
             return;
        }
        get_registers();
        std::cout << std::hex << std::setfill('0');
        std::cout << "$rax 0x" << std::setw(16) << regs_.rax << "   $rbx 0x" << std::setw(16) << regs_.rbx << "   $rcx 0x" << std::setw(16) << regs_.rcx << std::endl;
        std::cout << "$rdx 0x" << std::setw(16) << regs_.rdx << "   $rsi 0x" << std::setw(16) << regs_.rsi << "   $rdi 0x" << std::setw(16) << regs_.rdi << std::endl;
        std::cout << "$rbp 0x" << std::setw(16) << regs_.rbp << "   $rsp 0x" << std::setw(16) << regs_.rsp << "   $r8  0x" << std::setw(16) << regs_.r8  << std::endl;
        std::cout << "$r9  0x" << std::setw(16) << regs_.r9  << "   $r10 0x" << std::setw(16) << regs_.r10 << "   $r11 0x" << std::setw(16) << regs_.r11 << std::endl;
        std::cout << "$r12 0x" << std::setw(16) << regs_.r12 << "   $r13 0x" << std::setw(16) << regs_.r13 << "   $r14 0x" << std::setw(16) << regs_.r14 << std::endl;
        std::cout << "$r15 0x" << std::setw(16) << regs_.r15 << "   $rip 0x" << std::setw(16) << regs_.rip << "   $eflags 0x" << std::setw(16) << regs_.eflags << std::endl;
        std::cout << std::dec << std::setfill(' '); 
    }

    void set_breakpoint_common(unsigned long long addr, bool is_rva) {
        if (!program_loaded_ || child_pid_ <= 0) {
            std::cout << "** No program loaded to set breakpoint." << std::endl;
            return;
        }
        if (!is_address_in_executable_region(addr)) {
            std::cout << "** the target address is not valid." << std::endl;
            return;
        }

        if (breakpoints_map_.count(addr) && breakpoints_map_.at(addr).enabled) {
            std::cout << "** breakpoint already exists at 0x" << std::hex << addr << std::dec << "." << std::endl;
            return;
        }
        
        get_registers(); 
        unsigned char original_byte = read_memory_byte(addr);
        if (errno != 0 && original_byte == 0 && addr != 0) { 
            std::cout << "** failed to read memory at breakpoint address 0x" << std::hex << addr << std::dec << "." << std::endl;
            return;
        }
        write_memory_byte(addr, 0xCC); 

        breakpoints_map_.insert_or_assign(addr, Breakpoint(next_breakpoint_id_, addr, original_byte));
        breakpoint_id_to_addr_[next_breakpoint_id_] = addr;
        next_breakpoint_id_++;

        std::cout << std::hex << "** set a breakpoint at 0x" << addr << "." << std::dec << std::endl;
    }

    void set_breakpoint(const std::string& addr_str) {
        unsigned long long addr;
        try {
            addr = hex_to_ullong(addr_str);
        } catch (const std::exception& e) {
            std::cout << "** Invalid address format." << std::endl;
            return;
        }
        set_breakpoint_common(addr, false);
    }

    void set_breakpoint_rva(const std::string& offset_str) {
        unsigned long long offset;
         try {
            offset = hex_to_ullong(offset_str);
        } catch (const std::exception& e) {
            std::cout << "** Invalid offset format." << std::endl;
            return;
        }
        if (base_address_ == 0 && entry_point_ == 0) { // If both are zero, we likely failed to load/parse properly
            std::cout << "** base address not determined, cannot set RVA breakpoint." << std::endl;
            return;
        }
        // If base_address_ is 0, but entry_point is not (e.g. non-PIE where entry_point is absolute),
        // an RVA breakpoint relative to a 0 base might be intended to be relative to entry point's implicit base.
        // The spec's examples (hello is non-PIE, hola is PIE) show RVA for hello (0x400000 base) and hola (dynamic base).
        // Current base_address calculation should handle this.
        unsigned long long effective_base = base_address_;
        if (base_address_ == 0 && entry_point_ != 0) {
            // Heuristic for non-PIE if maps didn't give a clear base but we have an absolute entry.
            // This is less reliable. The PIE case (hola) is more critical for base_address.
            // For non-PIE like 'hello', base_address is usually 0x400000. If parse_proc_maps couldn't get it,
            // breakrva might be problematic.
            // The spec says "base address of the target binary". For non-PIE, this is its fixed load address.
            // For PIE, it's the ASLR'd load address.
            // If base_address_ is 0, it indicates an issue with its determination.
            // std::cout << "** Warning: base_address is 0, RVA might be incorrect." << std::endl;
        }


        unsigned long long addr = effective_base + offset;
        set_breakpoint_common(addr, true);
    }


    void info_breakpoints() {
        if (!program_loaded_) {
            std::cout << "** No program loaded." << std::endl;
            return;
        }
        // bool found_any = false;
        std::vector<std::pair<int, unsigned long long>> sorted_bps;
        for(const auto& pair_id_addr : breakpoint_id_to_addr_){
            // Ensure the breakpoint still exists in the main map and is enabled
            auto bp_map_it = breakpoints_map_.find(pair_id_addr.second);
            if(bp_map_it != breakpoints_map_.end() && bp_map_it->second.enabled){ 
                 sorted_bps.push_back({pair_id_addr.first, pair_id_addr.second});
            }
        }
        std::sort(sorted_bps.begin(), sorted_bps.end()); // Sort by ID

        if (sorted_bps.empty()) {
            std::cout << "** no breakpoints." << std::endl;
            return;
        }

        std::cout << "Num      Address" << std::endl;
        for (const auto& pair_id_addr : sorted_bps) {
             std::cout << std::left << std::setw(7) << pair_id_addr.first
                       << "0x" << std::hex << pair_id_addr.second << std::dec << std::endl;
        }
    }

    void delete_breakpoint(int id) {
        if (!program_loaded_ || child_pid_ <= 0) {
             std::cout << "** No program loaded to delete breakpoint." << std::endl;
            return;
        }
        auto id_it = breakpoint_id_to_addr_.find(id);
        if (id_it == breakpoint_id_to_addr_.end()) {
            std::cout << "** breakpoint " << id << " does not exist." << std::endl;
            return;
        }

        unsigned long long addr = id_it->second;
        auto bp_it = breakpoints_map_.find(addr);
        if (bp_it == breakpoints_map_.end() || !bp_it->second.enabled) {
            std::cout << "** breakpoint " << id << " does not exist (or already inactive)." << std::endl;
            breakpoint_id_to_addr_.erase(id_it); 
            if (bp_it != breakpoints_map_.end()) breakpoints_map_.erase(bp_it); // Clean up main map too if it was there but disabled
            return;
        }

        write_memory_byte(addr, bp_it->second.original_byte); 
        breakpoints_map_.erase(bp_it); 
        breakpoint_id_to_addr_.erase(id_it); 

        std::cout << "** delete breakpoint " << id << "." << std::endl;
    }

    void patch_memory(const std::string& addr_str, const std::string& hex_values_str) {
        if (!program_loaded_ || child_pid_ <= 0) {
            std::cout << "** No program loaded to patch memory." << std::endl;
            return;
        }
        unsigned long long start_addr;
        try {
            start_addr = hex_to_ullong(addr_str);
        } catch (const std::exception& e) {
            std::cout << "** Invalid address format for patch." << std::endl;
            return;
        }

        if (hex_values_str.length() % 2 != 0 || hex_values_str.length() > 2048 || hex_values_str.empty()) {
            std::cout << "** Invalid hex string for patch (must be non-empty, even length, max 2048 chars)." << std::endl;
            return;
        }

        std::vector<unsigned char> bytes_to_patch;
        for (size_t i = 0; i < hex_values_str.length(); i += 2) {
            std::string byte_str = hex_values_str.substr(i, 2);
            try {
                bytes_to_patch.push_back(static_cast<unsigned char>(std::stoul(byte_str, nullptr, 16)));
            } catch (const std::exception& e) {
                std::cout << "** Invalid hex byte value in patch string: " << byte_str << std::endl;
                return;
            }
        }

        for (size_t i = 0; i < bytes_to_patch.size(); ++i) {
            // For patching, we generally need writable memory. Executable is not always writable.
            // However, the spec example patches code segment. ptrace POKETEXT often bypasses memory permissions.
            // Let's keep the check with is_address_in_executable_region for now, as per spec context.
            // A more general debugger might check /proc/pid/maps for 'w' permission.
            if (!is_address_in_executable_region(start_addr + i)) { 
                std::cout << "** the target address is not valid (not in executable region for patching)." << std::endl;
                return;
            }
        }

        for (size_t i = 0; i < bytes_to_patch.size(); ++i) {
            unsigned long long current_patch_addr = start_addr + i;
            unsigned char byte_to_write = bytes_to_patch[i];

            auto bp_it = breakpoints_map_.find(current_patch_addr);
            if (bp_it != breakpoints_map_.end() && bp_it->second.enabled) {
                bp_it->second.original_byte = byte_to_write; 
            } else {
                write_memory_byte(current_patch_addr, byte_to_write);
            }
        }
        std::cout << std::hex << "** patch memory at 0x" << start_addr << "." << std::dec << std::endl;
    }

};


int main(int argc, char *argv[]) {
    Debugger sdb;
    if (argc > 1) {
        sdb.run(argv[1]);
    } else {
        sdb.run();
    }
    return 0;
}