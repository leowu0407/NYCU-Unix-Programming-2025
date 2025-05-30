// sdb.cpp
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <map>
#include <fstream>
#include <cstring>  // For strsignal, strlen, etc.
#include <cstdlib>  // For realpath, exit, stoll, stoi, strdup, free
#include <limits.h> // For PATH_MAX
#include <cerrno>   // For errno

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h> // For user_regs_struct
#include <unistd.h>   // For fork, exec, readlink, getpid etc.
#include <signal.h>   // For siginfo_t, SIGTRAP etc. Needed for PTRACE_GETSIGINFO
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

unsigned long long hex_to_ullong(std::string hex_str) {
    if (hex_str.rfind("0x", 0) == 0 || hex_str.rfind("0X", 0) == 0) {
        hex_str = hex_str.substr(2);
    }
    if (hex_str.empty()) {
        throw std::invalid_argument("hex_to_ullong: input string is empty after 0x removal");
    }
    return std::stoull(hex_str, nullptr, 16);
}

// Breakpoint struct is not strictly necessary with current map usage but can be kept for clarity
struct Breakpoint {
    int id;
    unsigned long long address;
    long original_data; // Stores the original data WORD at the breakpoint address

    Breakpoint() : id(-1), address(0), original_data(0) {}

    Breakpoint(int i, unsigned long long addr, long orig_data)
        : id(i), address(addr), original_data(orig_data) {}
};


class Debugger {
private: 
    pid_t child_pid_;
    bool program_loaded_;
    std::string current_program_path_;      // Absolute path to the program
    std::string user_program_path_display_; // Path as provided by user
    unsigned long long entry_point_from_elf_; // Entry point read from ELF header
    unsigned long long actual_loaded_entry_point_; // Actual entry point in memory (after ASLR for PIE)
    unsigned long long base_address_;  // Load address of the executable (for PIE/dynamic)
    unsigned long long load_offset_; // Offset due to ASLR (same as base_address_ for PIE)
    unsigned long long text_segment_elf_va_; // Virtual address of .text segment from ELF
    unsigned long long text_segment_size_;   // Size of .text segment from ELF
    unsigned long long text_segment_start_;  // Actual start address of .text in memory
    unsigned long long was_stopped_at_breakpoint_addr_; // If the previous stop was at a BP, this stores its address
    
    struct user_regs_struct regs_; // CPU registers
    int status_; // Wait status of child

    // breakpoints_map_: key is address, value is the original data WORD at that address
    std::map<unsigned long long, long> breakpoints_map_; 
    // breakpoint_id_to_addr_: key is user-facing ID, value is address
    std::map<int, unsigned long long> breakpoint_id_to_addr_; 
    int next_breakpoint_id_; // For generating new breakpoint IDs

    csh capstone_handle_; // Capstone disassembler handle
    // Stores pairs of [start_addr, end_addr) for executable memory regions of the target program
    std::vector<std::pair<unsigned long long, unsigned long long>> executable_regions_;
    
    bool in_syscall_entry_; // True if the next expected syscall event is an entry, false for an exit
    std::string current_command_; // Stores the current command being processed
    bool is_pie_or_dyn_cached_; // True if the loaded program is PIE or dynamically linked


public:
    Debugger() : 
        child_pid_(-1), 
        program_loaded_(false), 
        entry_point_from_elf_(0),
        actual_loaded_entry_point_(0), 
        base_address_(0),
        load_offset_(0),
        text_segment_elf_va_(0),
        text_segment_size_(0),
        text_segment_start_(0), 
        was_stopped_at_breakpoint_addr_(0),
        status_(0),
        next_breakpoint_id_(0), 
        capstone_handle_(0), 
        in_syscall_entry_(true), // Expect syscall entry first
        is_pie_or_dyn_cached_(false)
    {
        // Initialize Capstone
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle_) != CS_ERR_OK) {
            std::cerr << "** Capstone initialization failed." << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    ~Debugger() {
        if (capstone_handle_ != 0) {
            cs_close(&capstone_handle_);
        }
        // Ensure child process is killed if debugger exits
        if (child_pid_ > 0) {
            kill_program();
        }
    }

    // Main debugger loop
    void run(const std::string& initial_program_path_arg = "") {
        // Disable buffering for stdin and stdout for interactive use
        if (setvbuf(stdout, nullptr, _IONBF, 0) != 0) { /* Non-critical error for stdout */ }
        if (setvbuf(stdin, nullptr, _IONBF, 0) != 0) { /* Non-critical error for stdin */ }

        // If a program path is provided as a command-line argument, load it
        if (!initial_program_path_arg.empty()) {
            user_program_path_display_ = initial_program_path_arg;
            char* prog_name_c_str = strdup(initial_program_path_arg.c_str());
            if (!prog_name_c_str) { std::cerr << "** Memory allocation failed for program name." << std::endl; return; }
            char* argv_for_load[] = {prog_name_c_str, nullptr};
            load_program_internal(argv_for_load);
            free(prog_name_c_str);
        }

        std::string line;
        while (true) {
            // Prompt user for command
            std::cout << "(sdb) " << std::flush;
            if (!std::getline(std::cin, line)) { // Handle EOF (Ctrl+D)
                if (child_pid_ > 0) kill_program(); 
                break;
            }

            std::vector<std::string> args = split_string(line, ' ');
            if (args.empty() || args[0].empty()) { // Empty input
                continue;
            }

            current_command_ = args[0]; 

            // Command: load
            if (current_command_ == "load") {
                if (child_pid_ > 0) kill_program(); // Kill any existing program

                if (args.size() < 2) {
                    std::cerr << "** Usage: load [path to program]" << std::endl;
                } else {
                    user_program_path_display_ = args[1];
                    char* loaded_prog_name_c_str = strdup(args[1].c_str());
                    if (!loaded_prog_name_c_str) { std::cerr << "** Memory allocation failed for loaded program name." << std::endl; continue;}
                    char* argv_for_exec[] = {loaded_prog_name_c_str, nullptr}; // For execvp
                    load_program_internal(argv_for_exec);
                    free(loaded_prog_name_c_str);
                }
            } 
            // Command: exit/quit/q
            else if (current_command_ == "exit" || current_command_ == "quit" || current_command_ == "q") {
                kill_program();
                break;
            }
            // Commands requiring a loaded program
            else if (!program_loaded_) {
                if (current_command_ == "si" || current_command_ == "cont" || current_command_ == "info" ||
                    current_command_ == "break" || current_command_ == "breakrva" || current_command_ == "delete" ||
                    current_command_ == "patch" || current_command_ == "syscall") {
                    std::cout << "** please load a program first." << std::endl;
                } else if (!current_command_.empty()){ 
                    std::cout << "** Unknown command: " << current_command_ << std::endl;
                }
            } 
            // Program is loaded, process other commands
            else { 
                // Defensive check: if program terminated unexpectedly and not caught by handle_wait_status before prompt
                if (child_pid_ == -1 && (WIFEXITED(status_) || WIFSIGNALED(status_))) {
                    // This state should ideally be set by handle_wait_status.
                    // If program_loaded_ is true but child_pid_ is -1, it means termination happened.
                    // The message would have been printed by handle_wait_status.
                    // Resetting program_loaded_ here ensures the next prompt reflects this.
                     program_loaded_ = false; // Ensure prompt reflects termination
                     // No message here, as handle_wait_status should have printed it.
                     continue;
                }


                if (current_command_ == "si") {
                    step_instruction();
                } else if (current_command_ == "cont") {
                    continue_execution();
                } else if (current_command_ == "info") {
                    if (args.size() > 1 && args[1] == "reg") {
                        print_registers();
                    } else if (args.size() > 1 && args[1] == "break") {
                        info_breakpoints();
                    } else {
                        std::cout << "** Usage: info reg | info break" << std::endl;
                    }
                } else if (current_command_ == "break") {
                    if (args.size() < 2) {
                        std::cout << "** Usage: break [hex address]" << std::endl;
                    } else {
                        set_breakpoint(args[1]);
                    }
                } else if (current_command_ == "breakrva") {
                    if (args.size() < 2) {
                        std::cout << "** Usage: breakrva [hex offset]" << std::endl;
                    } else {
                        set_breakpoint_rva(args[1]);
                    }
                } else if (current_command_ == "delete") {
                    if (args.size() < 2) {
                        std::cout << "** Usage: delete [id]" << std::endl;
                    } else {
                        try {
                            delete_breakpoint(std::stoi(args[1]));
                        } catch (const std::exception& e) {
                            std::cout << "** Invalid breakpoint id format." << std::endl;
                        }
                    }
                } else if (current_command_ == "patch") {
                    if (args.size() < 3) {
                        std::cout << "** Usage: patch [hex address] [hex string]" << std::endl;
                    } else {
                        patch_memory(args[1], args[2]);
                    }
                } else if (current_command_ == "syscall") {
                    handle_syscall_command();
                }
                else if (!current_command_.empty()) {
                    std::cout << "** Unknown command: " << current_command_ << std::endl;
                }
            }
        }
    }

    // Terminates the currently loaded program and resets debugger state
    void kill_program() {
        if (child_pid_ > 0) {
            // Best-effort attempt to restore original bytes at breakpoint locations
            if (program_loaded_) { 
                for (auto const& [addr, original_data_word_snapshot] : breakpoints_map_) {
                    if (child_pid_ <=0) break; 
                    errno = 0;
                    long current_word_in_mem = peek_text(addr); // Read current memory (might have 0xCC)
                    if (errno == 0 && (current_word_in_mem & 0xFF) == 0xCC) { 
                        unsigned char original_first_byte = (unsigned char)(original_data_word_snapshot & 0xFFL);
                        long word_to_restore = (current_word_in_mem & ~0xFFL) | original_first_byte;
                        ptrace(PTRACE_POKETEXT, child_pid_, (void*)addr, (void*)word_to_restore);
                    } else if (errno == ESRCH) { 
                        child_pid_ = -1; 
                        break;
                    }
                }
            }
            
            if (child_pid_ > 0) { 
                 ptrace(PTRACE_KILL, child_pid_, nullptr, nullptr); 
                 waitpid(child_pid_, nullptr, 0); 
            }
        }
        // Reset all state variables
        child_pid_ = -1; program_loaded_ = false; 
        current_program_path_.clear(); user_program_path_display_.clear();
        entry_point_from_elf_ = 0; actual_loaded_entry_point_ = 0; base_address_ = 0; load_offset_ = 0;
        text_segment_elf_va_ = 0; text_segment_size_ = 0; text_segment_start_ = 0;
        was_stopped_at_breakpoint_addr_ = 0; status_ = 0;
        breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); next_breakpoint_id_ = 0;
        executable_regions_.clear(); in_syscall_entry_ = true; // Reset for next load
        is_pie_or_dyn_cached_ = false;
    }
    
    // Reads a word from the child's memory at a given address
    long peek_text(unsigned long long addr) {
        if (child_pid_ <= 0) return -1L; // No child to peek
        errno = 0;
        long data = ptrace(PTRACE_PEEKTEXT, child_pid_, (void*)addr, nullptr);
        if (errno != 0) { 
            if (errno == ESRCH && program_loaded_) { 
                // Child died, update state. This will be more robustly handled by handle_wait_status.
                program_loaded_ = false; 
                child_pid_ = -1;
            }
            return -1L; 
        }
        return data;
    }

    // Writes a word to the child's memory at a given address
    void poke_text(unsigned long long addr, long data) {
        if (child_pid_ <= 0) return; // No child to poke
        errno = 0;
        if (ptrace(PTRACE_POKETEXT, child_pid_, (void*)addr, (void*)data) < 0) {
            if (errno == ESRCH && program_loaded_) { 
                program_loaded_ = false; 
                child_pid_ = -1;
            }
        }
    }

    // Retrieves current register values from the child process
    void get_registers() {
        if (child_pid_ <= 0 || !program_loaded_ ) return; 
        if (ptrace(PTRACE_GETREGS, child_pid_, nullptr, &regs_) < 0) {
            if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
        }
    }

    // Sets register values in the child process
    void set_registers() {
        if (child_pid_ <= 0 || !program_loaded_) return;
        if (ptrace(PTRACE_SETREGS, child_pid_, nullptr, &regs_) < 0) {
            if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
        }
    }
    
    // Checks if a given address is within any known executable region of the target program
    bool is_address_in_executable_region(unsigned long long addr) {
        // Check primary .text segment (derived from ELF and maps) first
        if (text_segment_start_ != 0 && text_segment_size_ != 0) {
            if (addr >= text_segment_start_ && addr < text_segment_start_ + text_segment_size_) {
                return true;
            }
        }
        // Fallback to the general list of executable regions parsed from /proc/pid/maps
        for (const auto& region : executable_regions_) {
            if (addr >= region.first && addr < region.second) {
                return true;
            }
        }
        return false;
    }

    // Parses ELF headers and /proc/pid/maps to determine entry point, base address, and executable regions
    void parse_elf_and_get_abs_entry(const char* program_file_path) {
        std::ifstream elf_file(program_file_path, std::ios::binary);
        if (!elf_file) { 
            // File not found or accessible, clear relevant fields
            text_segment_elf_va_ = 0; text_segment_size_ = 0; entry_point_from_elf_ = 0; 
            is_pie_or_dyn_cached_ = false; // Assume not PIE if ELF can't be read
            return; 
        }

        Elf64_Ehdr ehdr;
        elf_file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
        if (elf_file.gcount() != static_cast<long>(sizeof(ehdr)) || 
            !(ehdr.e_ident[EI_MAG0] == ELFMAG0 && ehdr.e_ident[EI_MAG1] == ELFMAG1 &&
              ehdr.e_ident[EI_MAG2] == ELFMAG2 && ehdr.e_ident[EI_MAG3] == ELFMAG3)) { 
            text_segment_elf_va_ = 0; text_segment_size_ = 0; entry_point_from_elf_ = 0; 
            is_pie_or_dyn_cached_ = false;
            return; 
        }
        
        entry_point_from_elf_ = ehdr.e_entry; 
        is_pie_or_dyn_cached_ = (ehdr.e_type == ET_DYN);

        text_segment_elf_va_ = 0;
        text_segment_size_ = 0;

        // Attempt to find .text section to get its ELF virtual address and size
        if (ehdr.e_shoff != 0 && ehdr.e_shstrndx != SHN_UNDEF && ehdr.e_shstrndx < ehdr.e_shnum) {
            elf_file.seekg(ehdr.e_shoff, std::ios::beg);
            std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
            elf_file.read(reinterpret_cast<char*>(shdrs.data()), ehdr.e_shnum * sizeof(Elf64_Shdr));

            if (elf_file.gcount() == static_cast<long>(ehdr.e_shnum * sizeof(Elf64_Shdr)) &&
                shdrs[ehdr.e_shstrndx].sh_size > 0 && shdrs[ehdr.e_shstrndx].sh_type == SHT_STRTAB) { 
                std::vector<char> shstrtab_data(shdrs[ehdr.e_shstrndx].sh_size);
                elf_file.seekg(shdrs[ehdr.e_shstrndx].sh_offset, std::ios::beg);
                elf_file.read(shstrtab_data.data(), shdrs[ehdr.e_shstrndx].sh_size);
                if (elf_file.gcount() == static_cast<long>(shdrs[ehdr.e_shstrndx].sh_size)) {
                    for (const auto& sh : shdrs) {
                        if (sh.sh_name < shstrtab_data.size() && strcmp(&shstrtab_data[sh.sh_name], ".text") == 0) {
                            text_segment_elf_va_ = sh.sh_addr; 
                            text_segment_size_ = sh.sh_size;
                            break;
                        }
                    }
                }
            }
        }
        elf_file.close(); // Close ELF file after reading headers
        
        // Determine base_address_ from /proc/pid/maps
        base_address_ = 0; 
        std::string maps_path = "/proc/" + std::to_string(child_pid_) + "/maps";
        std::ifstream maps_file(maps_path);
        std::string line_map_parser; 
        std::string proc_exe_path; // Path to executable symlink in /proc
        char exe_path_buf[PATH_MAX + 1] = {0}; 
        std::string symlink_path = "/proc/" + std::to_string(child_pid_) + "/exe";
        ssize_t len_symlink = readlink(symlink_path.c_str(), exe_path_buf, PATH_MAX);
        if (len_symlink != -1) {
            exe_path_buf[len_symlink] = '\0'; 
            proc_exe_path = std::string(exe_path_buf);
        }

        unsigned long long lowest_map_start_addr_for_exe = -1ULL; 
        while(std::getline(maps_file, line_map_parser)){ 
            std::stringstream ss_map(line_map_parser);
            std::string addr_range_map, perms_map, offset_str_map, dev_map, inode_str_map, pathname_map;
            ss_map >> addr_range_map >> perms_map >> offset_str_map >> dev_map >> inode_str_map;
            std::getline(ss_map, pathname_map); 
            if (!pathname_map.empty() && pathname_map.front() == ' ') pathname_map.erase(0, pathname_map.find_first_not_of(" "));
            
            bool path_matches_target = false;
            if (!pathname_map.empty() && (pathname_map == current_program_path_ || (!proc_exe_path.empty() && pathname_map == proc_exe_path) ) ) {
                path_matches_target = true;
            }

            if(path_matches_target){
                try {
                    unsigned long long map_offset = hex_to_ullong(offset_str_map);
                    if(map_offset == 0){ // First segment of the executable's mapping in memory
                        unsigned long long start_addr_map_segment = hex_to_ullong(addr_range_map.substr(0, addr_range_map.find('-')));
                        if(lowest_map_start_addr_for_exe == -1ULL || start_addr_map_segment < lowest_map_start_addr_for_exe){
                            lowest_map_start_addr_for_exe = start_addr_map_segment;
                        }
                    }
                } catch(...) { /* ignore parsing errors for this map line */ }
            }
        }
        if (lowest_map_start_addr_for_exe != -1ULL) base_address_ = lowest_map_start_addr_for_exe;
        maps_file.close();

        // Calculate actual loaded entry point and load offset
        if (is_pie_or_dyn_cached_) {
            actual_loaded_entry_point_ = base_address_ + entry_point_from_elf_;
            load_offset_ = base_address_; 
        } else { 
            actual_loaded_entry_point_ = entry_point_from_elf_;
            load_offset_ = 0; // For non-PIE, ELF entry is absolute, load_offset is effectively 0 relative to ELF VAs.
                               // base_address_ from maps is the actual load address of the image.
        }
        
        // Calculate actual start of .text segment in memory
        if (text_segment_elf_va_ != 0 && text_segment_size_ != 0) { 
             text_segment_start_ = text_segment_elf_va_ + load_offset_;
        } else if (actual_loaded_entry_point_ != 0) { 
            // Fallback: if .text section info isn't available, try to find the mapped region containing the entry point.
             bool found_entry_region = false;
             std::ifstream maps_file_fallback(maps_path); // Re-open maps file
             std::string line_fallback;
             while(std::getline(maps_file_fallback, line_fallback)) {
                 std::stringstream ss_fb(line_fallback);
                 std::string range_fb, perms_fb, offset_fb, dev_fb, inode_fb, path_fb;
                 ss_fb >> range_fb >> perms_fb >> offset_fb >> dev_fb >> inode_fb;
                 std::getline(ss_fb, path_fb);
                 if (!path_fb.empty() && path_fb.front() == ' ') path_fb.erase(0, path_fb.find_first_not_of(" "));

                bool path_matches_fb = false;
                if (!path_fb.empty() && (path_fb == current_program_path_ || (!proc_exe_path.empty() && path_fb == proc_exe_path) ) ) {
                    path_matches_fb = true;
                }

                 if(path_matches_fb && perms_fb.find('x') != std::string::npos) { // Executable region of target
                     size_t hyphen_pos = range_fb.find('-');
                     if (hyphen_pos != std::string::npos) {
                         try {
                             unsigned long long region_start = hex_to_ullong(range_fb.substr(0, hyphen_pos));
                             unsigned long long region_end = hex_to_ullong(range_fb.substr(hyphen_pos + 1));
                             if (actual_loaded_entry_point_ >= region_start && actual_loaded_entry_point_ < region_end) {
                                 text_segment_start_ = region_start; // Use the start of this mapped region
                                 text_segment_size_ = region_end - region_start; // Use its size
                                 found_entry_region = true;
                                 break;
                             }
                         } catch (...) {/*continue*/}
                     }
                 }
             }
             maps_file_fallback.close();
             if (!found_entry_region) { // If no specific region for entry point found, make a guess
                 text_segment_start_ = base_address_ != 0 ? base_address_ : (actual_loaded_entry_point_ & ~(0xFFFULL)); 
                 text_segment_size_ = 0x2000; // Default guess for size
             }
        } else { // No entry point from ELF, no .text by name
            text_segment_start_ = base_address_; 
            text_segment_size_ = 0; 
        }

        // Populate executable_regions_ list from /proc/pid/maps
        executable_regions_.clear();
        std::ifstream maps_file_exec_regions(maps_path); // Re-open maps file
        std::string line_exec_regions; 
        while(std::getline(maps_file_exec_regions, line_exec_regions)) {
            std::stringstream ss_exec(line_exec_regions);
            std::string addr_range_exec, perms_exec, offset_exec_str, dev_exec, inode_exec_str, path_exec;
            ss_exec >> addr_range_exec >> perms_exec >> offset_exec_str >> dev_exec >> inode_exec_str;
            std::getline(ss_exec, path_exec); 
            if (!path_exec.empty() && path_exec.front() == ' ') path_exec.erase(0, path_exec.find_first_not_of(" "));
            
            if (perms_exec.find('x') != std::string::npos) { // If region is executable
                bool is_target_binary_region = false;
                if (!path_exec.empty() && (path_exec == current_program_path_ || (!proc_exe_path.empty() && path_exec == proc_exe_path))) {
                    is_target_binary_region = true;
                }
                // For "anon" example, allow executable anonymous regions.
                // For general disassembly, focus on target binary's regions + vdso/vsyscall.
                if (is_target_binary_region || 
                    (path_exec.empty() && perms_exec.find('x') != std::string::npos) || // For JIT/anon code
                    path_exec.find("[vdso]") != std::string::npos || 
                    path_exec.find("[vsyscall]") != std::string::npos ) {
                    size_t hyphen_pos_exec = addr_range_exec.find('-');
                    if (hyphen_pos_exec != std::string::npos) {
                        try {
                            executable_regions_.push_back({
                                hex_to_ullong(addr_range_exec.substr(0, hyphen_pos_exec)),
                                hex_to_ullong(addr_range_exec.substr(hyphen_pos_exec + 1))
                            });
                        } catch(...) { /* ignore parsing error for this region */ }
                    }
                }
            }
        }
        maps_file_exec_regions.close();
    }

    // Loads and prepares a new program for debugging
    void load_program_internal(char** argv_for_exec) {
        if (program_loaded_) { kill_program(); } // Ensure any previous program is gone
        
        // Reset all relevant states for the new program
        entry_point_from_elf_ = 0; actual_loaded_entry_point_ = 0; base_address_ = 0; load_offset_ = 0;
        text_segment_elf_va_ = 0; text_segment_size_ = 0; text_segment_start_ = 0; executable_regions_.clear();
        breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); next_breakpoint_id_ = 0; 
        is_pie_or_dyn_cached_ = false; was_stopped_at_breakpoint_addr_ = 0;
        status_ = 0; 
        in_syscall_entry_ = true; // Expect syscall entry first for a new program
        memset(&regs_, 0, sizeof(regs_));

        user_program_path_display_ = argv_for_exec[0]; // Store user-provided path for display

        // Get absolute path of the program
        char abs_program_path_buf[PATH_MAX];
        if (realpath(argv_for_exec[0], abs_program_path_buf) == NULL) {
            current_program_path_ = argv_for_exec[0]; // Use as-is if realpath fails
        } else {
            current_program_path_ = abs_program_path_buf; 
        }
        
        child_pid_ = fork();
        if (child_pid_ < 0) { perror("** fork failed"); program_loaded_ = false; return; }

        if (child_pid_ == 0) { // Child process: trace itself and exec the target program
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) { perror("** ptrace(TRACEME) failed"); _exit(EXIT_FAILURE); }
            // execvp will cause a SIGTRAP to be sent to the child after it successfully loads.
            if (execvp(current_program_path_.c_str(), argv_for_exec) < 0) { perror("** execvp failed"); _exit(EXIT_FAILURE); }
        } else { // Parent process: debugger
            if (waitpid(child_pid_, &status_, 0) < 0) { perror("** waitpid failed"); program_loaded_ = false; child_pid_ = -1; return;}
            
            if (!WIFSTOPPED(status_)) { // Child didn't stop as expected (e.g., exited immediately)
                std::cerr << "** Program '" << user_program_path_display_ << "' failed to start or exited/signaled immediately." << std::endl;
                child_pid_ = -1; program_loaded_ = false; return;
            }
            // Set ptrace options after the first stop
            if (ptrace(PTRACE_SETOPTIONS, child_pid_, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) < 0) {
                 // PTRACE_O_TRACESYSGOOD is important for distinguishing syscall SIGTRAPs.
                 // If this fails, syscall command might be less reliable.
                 // perror("** ptrace(PTRACE_SETOPTIONS) failed"); // Optional: log this warning
            }
            
            program_loaded_ = true; 
            // Parse ELF and memory maps now that the child is loaded
            parse_elf_and_get_abs_entry(current_program_path_.c_str());

            // If AT_ENTRY from auxv is needed as a fallback for actual_loaded_entry_point_
            if (actual_loaded_entry_point_ == 0 && entry_point_from_elf_ == 0 && base_address_ == 0) {
                std::string auxv_path = "/proc/" + std::to_string(child_pid_) + "/auxv";
                std::ifstream auxv_file(auxv_path, std::ios::binary);
                if (auxv_file) {
                    Elf64_auxv_t auxv_entry_struct; // Renamed to avoid conflict
                    while (auxv_file.read(reinterpret_cast<char*>(&auxv_entry_struct), sizeof(auxv_entry_struct))) {
                        if (auxv_entry_struct.a_type == AT_ENTRY) {
                            actual_loaded_entry_point_ = auxv_entry_struct.a_un.a_val;
                            break;
                        }
                        if (auxv_entry_struct.a_type == AT_NULL) break;
                    }
                    auxv_file.close();
                }
            }
             if (actual_loaded_entry_point_ == 0) { // Still zero after all attempts
                std::cerr << "** Could not determine entry point for " << user_program_path_display_ << std::endl;
                kill_program(); return;
            }
            
            get_registers(); 
            // For PIE/dynamic ELFs, the initial stop might be in the dynamic linker.
            // We need to run until the *target binary's* actual entry point.
            if (regs_.rip != actual_loaded_entry_point_ && actual_loaded_entry_point_ != 0) {
                long original_word_at_target_entry = peek_text(actual_loaded_entry_point_);
                if (errno != 0 && original_word_at_target_entry == -1L) { 
                    std::cerr << "** Failed to read memory at calculated program entry point: 0x" << std::hex << actual_loaded_entry_point_ << std::dec << std::endl;
                    kill_program(); return;
                }
                long temp_bp_word_at_target_entry = (original_word_at_target_entry & ~0xFFL) | 0xCC;
                poke_text(actual_loaded_entry_point_, temp_bp_word_at_target_entry); 

                ptrace(PTRACE_CONT, child_pid_, nullptr, nullptr);
                if (waitpid(child_pid_, &status_, 0) < 0) { perror("** waitpid after temp BP to entry failed"); kill_program(); return;}

                if (child_pid_ > 0) poke_text(actual_loaded_entry_point_, original_word_at_target_entry); // Restore original byte
                
                if (WIFSTOPPED(status_) && WSTOPSIG(status_) == SIGTRAP) {
                    get_registers();
                    // After hitting the temp BP, RIP is usually BP_addr + 1. Adjust it to be AT the entry.
                    if (regs_.rip == actual_loaded_entry_point_ + 1) { 
                        regs_.rip--; 
                        set_registers(); 
                    } else if (regs_.rip != actual_loaded_entry_point_){
                        // If RIP is somewhere else unexpected, but we should be at entry.
                        regs_.rip = actual_loaded_entry_point_; 
                        set_registers();
                    }
                } else { 
                    std::cerr << "** Failed to stop at program entry point after continuing from linker." << std::endl;
                    if (WIFEXITED(status_) || WIFSIGNALED(status_)) handle_wait_status(); else kill_program();
                    return;
                }
            }
            
            get_registers(); // Ensure regs_ are current for disassembly
            
            std::cout << "** program '" << user_program_path_display_ << "' loaded. entry point: 0x" << std::hex << actual_loaded_entry_point_ << "." << std::dec << std::endl;
            disassemble_instructions(regs_.rip, 5); 
            was_stopped_at_breakpoint_addr_ = 0; // Not stopped at a user-set BP initially
        }
    }
    
    // Disassembles 'count' instructions starting from 'start_address'
    void disassemble_instructions(unsigned long long start_address, int count) {
        if (!program_loaded_ || child_pid_ <= 0) return;

        // Initial check for the start_address itself
        if (!is_address_in_executable_region(start_address) && start_address !=0) {
             std::cout << "** the address is out of the range of the executable region." << std::endl;
             return;
        }

        const int MAX_INSTR_BYTES_PER_INS = 15; 
        std::vector<unsigned char> instruction_bytes_buffer; // Use a vector for dynamic sizing
        // Reserve enough space to avoid frequent reallocations
        instruction_bytes_buffer.reserve(MAX_INSTR_BYTES_PER_INS * count + MAX_INSTR_BYTES_PER_INS); 

        unsigned long long current_addr_for_mem_read = start_address;
        // Aim to read enough bytes for 'count' instructions, plus some buffer for Capstone.
        size_t target_bytes_to_read_for_disassembly = MAX_INSTR_BYTES_PER_INS * (count + 2); // Read a bit more for context

        for (size_t total_bytes_copied_to_buffer = 0; total_bytes_copied_to_buffer < target_bytes_to_read_for_disassembly; ) {
            if (child_pid_ <=0) break; // Child process died

            // Stop reading if current_addr_for_mem_read goes out of known executable regions (after the first word)
            if (total_bytes_copied_to_buffer > 0 && !is_address_in_executable_region(current_addr_for_mem_read) && current_addr_for_mem_read != 0) {
                break;
            }
            
            long memory_word_data = peek_text(current_addr_for_mem_read); // Read a word (typically 8 bytes)
            if (errno != 0 && memory_word_data == -1L) { // Error reading memory
                if (total_bytes_copied_to_buffer == 0 && !is_address_in_executable_region(start_address)) {
                    // This case is handled by the initial check at the function top.
                }
                break; 
            }

            // Copy bytes from the read word into our buffer, substituting original bytes for breakpoints
            for (size_t byte_idx_in_word = 0; byte_idx_in_word < sizeof(long); ++byte_idx_in_word) {
                if (total_bytes_copied_to_buffer >= target_bytes_to_read_for_disassembly) break;
                
                unsigned long long actual_byte_address_in_memory = current_addr_for_mem_read + byte_idx_in_word;
                unsigned char byte_value_from_memory = (reinterpret_cast<unsigned char*>(&memory_word_data))[byte_idx_in_word];
                
                auto bp_iterator = breakpoints_map_.find(actual_byte_address_in_memory); 
                if (bp_iterator != breakpoints_map_.end()) { 
                    // This byte IS a breakpoint location. Use its stored original LSB.
                    instruction_bytes_buffer.push_back((unsigned char)(bp_iterator->second & 0xFF)); 
                } else {
                    instruction_bytes_buffer.push_back(byte_value_from_memory);
                }
                total_bytes_copied_to_buffer++;
            }
            current_addr_for_mem_read += sizeof(long); // Move to the next word
        }

        if (instruction_bytes_buffer.empty()) {
            if (is_address_in_executable_region(start_address)) { 
                 std::cout << "** failed to read instructions at 0x" << std::hex << start_address << std::dec << "." << std::endl;
            } // Else, the initial check for start_address already printed the OOR message.
            return;
        }

        cs_insn *capstone_insn_array; // Array of disassembled instructions from Capstone
        size_t num_insns_disassembled_by_capstone = cs_disasm(capstone_handle_, 
                                                            instruction_bytes_buffer.data(), 
                                                            instruction_bytes_buffer.size(), 
                                                            start_address, 
                                                            0, // Disassemble all instructions in buffer
                                                            &capstone_insn_array); 

        std::cout << std::left; // Align output to the left

        size_t instructions_displayed_count = 0;
        bool oor_message_already_printed = false;
        unsigned long long address_after_last_displayed_instruction = start_address;

        if (num_insns_disassembled_by_capstone > 0) {
            for (size_t i = 0; i < num_insns_disassembled_by_capstone && instructions_displayed_count < static_cast<size_t>(count); ++i) {
                // Check if the current instruction's address is in an executable region
                if (!is_address_in_executable_region(capstone_insn_array[i].address) && capstone_insn_array[i].address !=0 ) {
                    if (instructions_displayed_count > 0) { // If some instructions were already printed
                         std::cout << "** the address is out of the range of the executable region." << std::endl;
                         oor_message_already_printed = true;
                    }
                    // If instructions_displayed_count is 0, the initial check for start_address should have caught it.
                    break; 
                }

                // Print: address, raw bytes, mnemonic, operands
                std::cout << "      " << std::hex << capstone_insn_array[i].address << ": " << std::dec; 
                std::string instruction_bytes_hex_str;
                for (size_t j = 0; j < capstone_insn_array[i].size; ++j) {
                    std::stringstream temp_ss;
                    temp_ss << std::setw(2) << std::setfill('0') << std::hex << (int)capstone_insn_array[i].bytes[j];
                    instruction_bytes_hex_str += (j == 0 ? "" : " ") + temp_ss.str();
                }
                std::cout << std::left << std::setw(33) << instruction_bytes_hex_str; 
                std::cout << std::setw(10) << capstone_insn_array[i].mnemonic; 
                std::cout << capstone_insn_array[i].op_str << std::endl;
                
                instructions_displayed_count++;
                address_after_last_displayed_instruction = capstone_insn_array[i].address + capstone_insn_array[i].size;
            }
            
            cs_free(capstone_insn_array, num_insns_disassembled_by_capstone); // Free Capstone's memory
            
            // If fewer than 'count' instructions were displayed, and no OOR message yet,
            // check if the *next* instruction would have been OOR.
            if (instructions_displayed_count < static_cast<size_t>(count) && !oor_message_already_printed) {
                if (instructions_displayed_count > 0 || num_insns_disassembled_by_capstone == 0) { // Only if we tried to display or capstone found nothing
                     if (!is_address_in_executable_region(address_after_last_displayed_instruction) && address_after_last_displayed_instruction != 0 && address_after_last_displayed_instruction != start_address) {
                        std::cout << "** the address is out of the range of the executable region." << std::endl;
                     }
                }
            }
        } else { // cs_disasm returned 0 instructions
            if (is_address_in_executable_region(start_address) && !instruction_bytes_buffer.empty()){
                // Read bytes, but Capstone couldn't disassemble. Could be invalid opcodes.
                // Spec doesn't explicitly cover this; focuses on OOR for address.
            }
        }
        std::cout << std::right << std::flush; 
    }

    // Handles the status of the child process after it stops or terminates
    void handle_wait_status() { 
        if (child_pid_ <= 0 && !(WIFEXITED(status_) || WIFSIGNALED(status_))) { 
            // No active child, or status doesn't indicate exit/signal (should not happen if child_pid_ <=0)
            return; 
        }

        if (WIFEXITED(status_)) {
            std::cout << "** the target program terminated." << std::endl;
            program_loaded_ = false; child_pid_ = -1; was_stopped_at_breakpoint_addr_ = 0; 
            breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); text_segment_elf_va_ = 0; text_segment_size_ = 0;
            executable_regions_.clear(); next_breakpoint_id_ = 0; load_offset_ = 0;
            actual_loaded_entry_point_ = 0; base_address_ = 0; entry_point_from_elf_ = 0;
            text_segment_start_ = 0; in_syscall_entry_ = true; // Reset for next load
            return;
        } else if (WIFSIGNALED(status_)) {
            std::cout << "** the target program terminated by signal " << strsignal(WTERMSIG(status_)) << "." << std::endl;
            program_loaded_ = false; child_pid_ = -1; was_stopped_at_breakpoint_addr_ = 0; 
            breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); text_segment_elf_va_ = 0; text_segment_size_ = 0;
            executable_regions_.clear(); next_breakpoint_id_ = 0; load_offset_ = 0;
            actual_loaded_entry_point_ = 0; base_address_ = 0; entry_point_from_elf_ = 0;
            text_segment_start_ = 0; in_syscall_entry_ = true; // Reset for next load
            return;
        }
        else if (WIFSTOPPED(status_)) {
            int sig = WSTOPSIG(status_);
            get_registers(); 
            
            if (child_pid_ <= 0) { // Child might have died during get_registers or other ptrace ops
                 if (program_loaded_) { program_loaded_ = false; } // Ensure consistency
                 was_stopped_at_breakpoint_addr_ = 0; 
                 return;
            }

            bool event_handled_and_disassembled = false;
            unsigned long long rip_as_reported_by_kernel = regs_.rip; 

            // This flag indicates if the *current* stop is at a breakpoint whose original instruction
            // has just been restored by this function. It's set after restoring.
            // `was_stopped_at_breakpoint_addr_` is reset at the start of this function for the current event.
            unsigned long long previous_bp_addr_if_any = was_stopped_at_breakpoint_addr_; // Store for context if needed
            was_stopped_at_breakpoint_addr_ = 0; // Reset for the current stop event processing

            if (sig == SIGTRAP) {
                // Check for Breakpoint Hit (INT3 instruction)
                // RIP will be at address_of_0xCC + 1
                unsigned long long potential_bp_addr_from_int3 = rip_as_reported_by_kernel - 1; 
                auto bp_iter_from_int3 = breakpoints_map_.find(potential_bp_addr_from_int3);
                
                // Check for Single-Step landing directly on a Breakpoint Address
                // This might happen if a single step lands on an instruction that has 0xCC
                auto bp_iter_direct_land = breakpoints_map_.find(rip_as_reported_by_kernel);

                if (bp_iter_from_int3 != breakpoints_map_.end()) { // Common case: PTRACE_CONT hits an INT3
                    regs_.rip = potential_bp_addr_from_int3; // Adjust RIP to point AT the breakpoint instruction
                    set_registers();        

                    std::cout << "** hit a breakpoint at 0x" << std::hex << regs_.rip << "." << std::dec << std::endl;

                    // Restore the original instruction word at the breakpoint address
                    poke_text(regs_.rip, bp_iter_from_int3->second); 
                    was_stopped_at_breakpoint_addr_ = regs_.rip; // Mark that we are now stopped AT this restored BP
                    disassemble_instructions(regs_.rip, 5);
                    event_handled_and_disassembled = true;
                }
                // This case (single-step landing on an active 0xCC) should be less common if BP re-arming is correct.
                else if (bp_iter_direct_land != breakpoints_map_.end()) { 
                    // RIP is already at the breakpoint address.
                    std::cout << "** hit a breakpoint at 0x" << std::hex << regs_.rip << "." << std::dec << std::endl;
                    poke_text(regs_.rip, bp_iter_direct_land->second); 
                    was_stopped_at_breakpoint_addr_ = regs_.rip;    
                    disassemble_instructions(regs_.rip, 5);
                    event_handled_and_disassembled = true;
                }
                // Check for Syscall trap (if not a breakpoint)
                else if ( (WSTOPSIG(status_) == (SIGTRAP | 0x80)) || // Caused by PTRACE_O_TRACESYSGOOD
                          (current_command_ == "syscall" && sig == SIGTRAP)    // Fallback for PTRACE_SYSCALL if plain SIGTRAP
                        )
                { 
                    // This block is reached if SIGTRAP was not handled as a breakpoint above.
                    unsigned long long syscall_instruction_address = regs_.rip;
                    // For syscall (0f 05), RIP is *after* the instruction. Address of syscall is rip - 2.
                    if (regs_.rip >= 2) { 
                        syscall_instruction_address = regs_.rip - 2;
                    } else {
                        // This is unexpected for a syscall stop. Fall through to default disassembly.
                    }

                    long syscall_number = regs_.orig_rax; // Syscall number in orig_rax before syscall
                    long syscall_return_value = regs_.rax;  // Return value in rax after syscall exit

                    if (in_syscall_entry_) { // Expecting a syscall entry
                        std::cout << "** enter a syscall(" << std::dec << syscall_number << ") at 0x" << std::hex << syscall_instruction_address << "." << std::dec << std::endl;
                        in_syscall_entry_ = false; // Next PTRACE_SYSCALL will be for exit
                    } else { // Expecting a syscall exit
                        std::cout << "** leave a syscall(" << std::dec << syscall_number << ") = " << std::dec << syscall_return_value;
                        std::cout << " at 0x" << std::hex << syscall_instruction_address << "." << std::dec << std::endl;
                        in_syscall_entry_ = true; // Next PTRACE_SYSCALL will be for entry
                    }
                    disassemble_instructions(syscall_instruction_address, 5);
                    event_handled_and_disassembled = true;
                }
                // Other SIGTRAPs (e.g. from PTRACE_SINGLESTEP not hitting a known BP) will fall through.
            } else if (sig == SIGWINCH) { // Window resize signal
                if (program_loaded_ && child_pid_ > 0) {
                    ptrace(PTRACE_CONT, child_pid_, nullptr, (void*)((long)sig)); // Pass signal to child
                    if (waitpid(child_pid_, &status_, 0) < 0 ) { 
                        if(program_loaded_ && child_pid_ > 0) { child_pid_ = -1; program_loaded_ = false;} 
                    }
                    // Recursively call handle_wait_status to process the new state after passing SIGWINCH
                    if (child_pid_ > 0 && program_loaded_) handle_wait_status(); 
                    return; // SIGWINCH and its immediate effect are handled.
                }
            } else { // Other signals (SIGSEGV, SIGILL, etc.)
                if (program_loaded_ && child_pid_ > 0) { 
                    std::cout << "** Child stopped by signal " << strsignal(sig) << " (SIG=" << sig << ")" << std::endl;
                }
            }

            // If the event was not a recognized breakpoint or handled syscall trap,
            // and the program is still loaded, disassemble from the current RIP.
            // This covers single-step completions or stops from other signals.
            if (!event_handled_and_disassembled && program_loaded_ && child_pid_ > 0) {
                disassemble_instructions(rip_as_reported_by_kernel, 5);
            }
        }
    }

    // Executes a single instruction
    void step_instruction() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        
        get_registers();
        unsigned long long rip_before_step = regs_.rip;

        // Check if we are currently stopped AT a breakpoint whose original instruction was restored.
        // `was_stopped_at_breakpoint_addr_` is set by `handle_wait_status` if it restored a BP at current RIP.
        bool stepping_from_active_restored_bp = (was_stopped_at_breakpoint_addr_ == rip_before_step && was_stopped_at_breakpoint_addr_ != 0);
        
        // Perform the single step
        if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) { 
            if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; } 
            return; 
        }
        if (waitpid(child_pid_, &status_, 0) < 0) { 
            if (program_loaded_ && child_pid_ > 0) { child_pid_ = -1; program_loaded_ = false; } 
            return;
        }

        // After the single step, if we stepped *off* a breakpoint, re-insert the 0xCC for that breakpoint.
        if (stepping_from_active_restored_bp) { 
            auto bp_iterator = breakpoints_map_.find(rip_before_step); // Find the BP we were on
            if (bp_iterator != breakpoints_map_.end()) { 
                if (child_pid_ > 0 && program_loaded_) { // Check if child is still valid
                    long rearm_breakpoint_word = (bp_iterator->second & ~0xFFL) | 0xCC; // Use original data for non-0xCC bytes
                    poke_text(rip_before_step, rearm_breakpoint_word);
                }
            }
        }
        
        handle_wait_status(); // Process the state after the single step
    }

    // Continues program execution until a breakpoint or termination
    void continue_execution() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        
        get_registers();
        unsigned long long rip_at_continue_start = regs_.rip;

        // If currently stopped AT a breakpoint (original instruction restored),
        // we must first single-step over this instruction, then re-insert 0xCC, then PTRACE_CONT.
        if (was_stopped_at_breakpoint_addr_ == rip_at_continue_start && was_stopped_at_breakpoint_addr_ != 0) {
            if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) { 
                if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
                return; 
            }
            int temp_status_after_single_step; 
            if (waitpid(child_pid_, &temp_status_after_single_step, 0) < 0) {
                if (program_loaded_ && child_pid_ > 0) {child_pid_ = -1; program_loaded_ = false;} 
                return;
            }

            // Re-arm the breakpoint we just stepped over
            if (child_pid_ > 0 && program_loaded_) { 
                auto bp_iterator = breakpoints_map_.find(rip_at_continue_start);
                if (bp_iterator != breakpoints_map_.end()) { 
                    long rearm_breakpoint_word = (bp_iterator->second & ~0xFFL) | 0xCC;
                    poke_text(rip_at_continue_start, rearm_breakpoint_word);
                }
            } else { // Child died or problem during the single step
                status_ = temp_status_after_single_step; 
                handle_wait_status(); 
                return; 
            }

            // If program terminated or had another critical stop during this single step
            if (WIFEXITED(temp_status_after_single_step) || WIFSIGNALED(temp_status_after_single_step)) {
                status_ = temp_status_after_single_step; 
                handle_wait_status(); 
                return; 
            }
            // If the single step hit another breakpoint, handle_wait_status (called later) will report it.
            status_ = temp_status_after_single_step; // Update main status for PTRACE_CONT
        }
        
        // Now, perform the PTRACE_CONT
        if (child_pid_ > 0 && program_loaded_) { 
            if (ptrace(PTRACE_CONT, child_pid_, nullptr, nullptr) < 0) { 
                if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
                return; 
            }
            if (waitpid(child_pid_, &status_, 0) < 0) {
                if (program_loaded_ && child_pid_ > 0) {child_pid_ = -1; program_loaded_ = false;}
                return;
            }
            handle_wait_status(); // Handle the result of PTRACE_CONT
        }
    }

    // Handles the 'syscall' command: executes until next syscall entry/exit
    void handle_syscall_command() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        get_registers();
        unsigned long long rip_at_cmd_start = regs_.rip;
        
        // If currently stopped AT a breakpoint, single-step over it first.
        if (was_stopped_at_breakpoint_addr_ == rip_at_cmd_start && was_stopped_at_breakpoint_addr_ != 0) {
            if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) { 
                if (errno == ESRCH) {program_loaded_=false; child_pid_=-1;} return; 
            }
            int temp_status;
            if (waitpid(child_pid_, &temp_status, 0) < 0) { 
                if (program_loaded_&&child_pid_>0) {program_loaded_=false; child_pid_=-1;} return;
            }
            
            // Re-arm the breakpoint
            if (child_pid_ > 0 && program_loaded_) {
                auto bp_it = breakpoints_map_.find(rip_at_cmd_start);
                if (bp_it != breakpoints_map_.end()) {
                    long rearm_word = (bp_it->second & ~0xFFL) | 0xCC;
                    poke_text(rip_at_cmd_start, rearm_word);
                }
            } else { status_ = temp_status; handle_wait_status(); return; }

            // If single step led to termination or another breakpoint, handle it and return.
            // The user will need to issue 'syscall' again.
            if (WIFEXITED(temp_status) || WIFSIGNALED(temp_status) ) {
                status_ = temp_status; handle_wait_status(); return;
            }
            status_ = temp_status; 
            if (WIFSTOPPED(status_) && WSTOPSIG(status_) == SIGTRAP) {
                 get_registers(); 
                 unsigned long long current_rip_after_step = regs_.rip;
                 // Check if this SIGTRAP is due to hitting another breakpoint
                 bool hit_another_bp = breakpoints_map_.count(current_rip_after_step -1) || breakpoints_map_.count(current_rip_after_step);
                 if(hit_another_bp) {
                    handle_wait_status(); // Report the breakpoint hit
                    return; // Do not proceed to PTRACE_SYSCALL for this 'syscall' command instance.
                 }
            }
        }
        
        // Proceed with PTRACE_SYSCALL. The `in_syscall_entry_` flag (managed by handle_wait_status)
        // will determine if the next stop is treated as an entry or exit.
        if (child_pid_ > 0 && program_loaded_) {
            if (ptrace(PTRACE_SYSCALL, child_pid_, nullptr, nullptr) < 0) {
                if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
                return;
            }
            if (waitpid(child_pid_, &status_, 0) < 0) {
                if(program_loaded_ && child_pid_ > 0) {child_pid_ = -1; program_loaded_ = false;} 
                return;
            }
            handle_wait_status(); // Process the stop from PTRACE_SYSCALL
        }
    }

    // Prints current register values
    void print_registers() {
        if (!program_loaded_ || child_pid_ <=0) { return; }
        if (ptrace(PTRACE_GETREGS, child_pid_, nullptr, &regs_) < 0) {
            if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; } 
            return;
        }

        std::ios_base::fmtflags original_flags = std::cout.flags(); 
        std::cout << std::hex << std::setfill('0');
        // Adjusted spacing for better alignment based on sample output
        std::cout << "$rax 0x" << std::setw(16) << regs_.rax << "   $rbx 0x" << std::setw(16) << regs_.rbx << "   $rcx 0x" << std::setw(16) << regs_.rcx << std::endl;
        std::cout << "$rdx 0x" << std::setw(16) << regs_.rdx << "   $rsi 0x" << std::setw(16) << regs_.rsi << "   $rdi 0x" << std::setw(16) << regs_.rdi << std::endl;
        std::cout << "$rbp 0x" << std::setw(16) << regs_.rbp << "   $rsp 0x" << std::setw(16) << regs_.rsp << "   $r8  0x" << std::setw(16) << regs_.r8  << std::endl;
        std::cout << "$r9  0x" << std::setw(16) << regs_.r9  << "   $r10 0x" << std::setw(16) << regs_.r10 << "   $r11 0x" << std::setw(16) << regs_.r11 << std::endl;
        std::cout << "$r12 0x" << std::setw(16) << regs_.r12 << "   $r13 0x" << std::setw(16) << regs_.r13 << "   $r14 0x" << std::setw(16) << regs_.r14 << std::endl;
        std::cout << "$r15 0x" << std::setw(16) << regs_.r15 << "   $rip 0x" << std::setw(16) << regs_.rip << "   $eflags 0x" << std::setw(16) << regs_.eflags << std::endl;
        std::cout.flags(original_flags); // Restore original cout flags
    }

    // Common logic for setting a breakpoint (absolute or RVA)
    void set_breakpoint_common(unsigned long long addr, bool is_rva_command) {
        if (!program_loaded_ || child_pid_ <= 0) { return; }
        
        bool is_valid_address_for_breakpoint = false;
        // Check primary .text segment first
        if (text_segment_start_ != 0 && text_segment_size_ != 0) { 
            if (addr >= text_segment_start_ && addr < text_segment_start_ + text_segment_size_) {
                is_valid_address_for_breakpoint = true;
            }
        }
        // If not in primary .text, check all other known executable regions
        if (!is_valid_address_for_breakpoint) { 
            for(const auto& region : executable_regions_){
                if(addr >= region.first && addr < region.second){
                    is_valid_address_for_breakpoint = true;
                    break;
                }
            }
        }
        // Last resort check if no regions are known (e.g. for "anon" example before full parsing)
        if (!is_valid_address_for_breakpoint && addr != 0 && executable_regions_.empty() && text_segment_size_ == 0) {
            errno = 0;
            peek_text(addr); // Try to read from the address
            if (errno == 0) is_valid_address_for_breakpoint = true; // If readable, assume valid for BP for now
        }

        if (!is_valid_address_for_breakpoint) { 
            std::cout << "** the target address is not valid." << std::endl; return;
        }

        // Check if breakpoint already exists at this address
        if (breakpoints_map_.count(addr)) { 
             // Spec doesn't say what to do. GDB might reconfirm.
             // For simplicity, if already set, just confirm.
             std::cout << "** set a breakpoint at 0x" << std::hex << addr << "." << std::dec << std::endl;
             return;
        }
        
        long original_memory_word = peek_text(addr); // Read the original word from memory
        if (errno != 0 && original_memory_word == -1L) { // Check errno as -1L can be valid data
            std::cout << "** the target address is not valid." << std::endl; return;
        }
        
        breakpoints_map_[addr] = original_memory_word; // Store the original word
        breakpoint_id_to_addr_[next_breakpoint_id_] = addr; // Map ID to address
        
        long breakpoint_word = (original_memory_word & ~0xFFL) | 0xCC; // Place 0xCC (INT3) in the LSB
        poke_text(addr, breakpoint_word); // Write the INT3 instruction
        
        std::cout << "** set a breakpoint at 0x" << std::hex << addr << "." << std::dec << std::endl;
        next_breakpoint_id_++;
    }

    // Sets a breakpoint at an absolute address
    void set_breakpoint(const std::string& addr_str) {
        unsigned long long addr;
        try { addr = hex_to_ullong(addr_str); } 
        catch (const std::exception& e) { std::cout << "** the target address is not valid." << std::endl; return; }
        set_breakpoint_common(addr, false);
    }

    // Sets a breakpoint at an address relative to the program's base (RVA)
    void set_breakpoint_rva(const std::string& offset_str) {
        unsigned long long offset;
        try { offset = hex_to_ullong(offset_str); } 
        catch (const std::exception& e) { std::cout << "** the target address is not valid." << std::endl; return; }
        
        // base_address_ is determined during program load from /proc/pid/maps
        unsigned long long addr = base_address_ + offset; 
        set_breakpoint_common(addr, true);
    }

    // Displays information about currently set breakpoints
    void info_breakpoints() {
        if (!program_loaded_) { return; } 
        std::vector<std::pair<int, unsigned long long>> active_breakpoints_for_display;
        // Iterate through ID-to-address map to maintain ID order and check if still active
        for(const auto& id_addr_pair : breakpoint_id_to_addr_){
            if(breakpoints_map_.count(id_addr_pair.second)){ // Check if still in the main breakpoints_map_
                active_breakpoints_for_display.push_back({id_addr_pair.first, id_addr_pair.second});
            }
        }
        // Sort by ID for consistent display order
        std::sort(active_breakpoints_for_display.begin(), active_breakpoints_for_display.end()); 

        if (active_breakpoints_for_display.empty()) { std::cout << "** no breakpoints." << std::endl; return; }

        std::cout << "Num     Address" << std::endl; // Header with spacing
        for (const auto& bp_info : active_breakpoints_for_display) {
            std::cout << std::left << std::setw(8) << bp_info.first // Print ID
                      << "0x" << std::hex << bp_info.second << std::dec << std::endl; // Print address
        }
    }

    // Deletes a breakpoint by its ID
    void delete_breakpoint(int id) {
        if (!program_loaded_ || child_pid_ <= 0) { return; }
        auto id_iterator = breakpoint_id_to_addr_.find(id);
        if (id_iterator == breakpoint_id_to_addr_.end()) { // Breakpoint ID not found
            std::cout << "** breakpoint " << id << " does not exist." << std::endl; return;
        }

        unsigned long long addr_to_delete = id_iterator->second;
        auto bp_data_iterator = breakpoints_map_.find(addr_to_delete);
        if (bp_data_iterator == breakpoints_map_.end()) { 
            // ID exists in id_to_addr map, but not in main breakpoints_map_ (inconsistent state)
            std::cout << "** breakpoint " << id << " does not exist (internal error - map inconsistent)." << std::endl;
            breakpoint_id_to_addr_.erase(id_iterator); // Clean up ID map
            return;
        }

        long original_word_snapshot_when_bp_set = bp_data_iterator->second; 
        
        if (child_pid_ > 0 && program_loaded_) { // Ensure child is alive
            errno = 0;
            long current_word_in_memory_at_bp = peek_text(addr_to_delete); // Read current memory (should have 0xCC)

            if (errno == 0) { // Successfully read current memory
                // Restore only the original first byte, leaving other bytes (addr+1 to addr+7)
                // as they are in current_word_in_memory, to preserve any patches made by 'patch' command.
                unsigned char original_first_byte_of_instruction = (unsigned char)(original_word_snapshot_when_bp_set & 0xFFL);
                long word_to_restore_to_memory = (current_word_in_memory_at_bp & ~0xFFL) | original_first_byte_of_instruction;
                poke_text(addr_to_delete, word_to_restore_to_memory);
            } else if (errno != ESRCH) { 
                // Peek failed for a reason other than child death (e.g. EIO, EFAULT).
                // Try restoring the full original word snapshot as a fallback.
                poke_text(addr_to_delete, original_word_snapshot_when_bp_set);
            }
            // If errno was ESRCH from peek_text, child_pid_ might have been set to -1.
            // No further poke needed if child is gone. poke_text itself handles ESRCH.
        }

        breakpoints_map_.erase(bp_data_iterator); // Remove from main breakpoint data map
        breakpoint_id_to_addr_.erase(id_iterator); // Remove from ID map
        std::cout << "** delete breakpoint " << id << "." << std::endl;
    }

    // Patches memory at a given address with a hex string
    void patch_memory(const std::string& addr_str, const std::string& hex_values_str) {
        if (!program_loaded_ || child_pid_ <= 0) { return; }
        unsigned long long start_patch_addr;
        try { start_patch_addr = hex_to_ullong(addr_str); } 
        catch (const std::exception& e) { std::cout << "** the target address is not valid." << std::endl; return; }

        // Validate hex string format and length
        if (hex_values_str.length() % 2 != 0 || hex_values_str.length() > 2048 || hex_values_str.empty()) {
            std::cout << "** the target address is not valid (invalid hex string format/length)." << std::endl; return;
        }

        // Convert hex string to bytes
        std::vector<unsigned char> bytes_to_write_to_memory;
        for (size_t i = 0; i < hex_values_str.length(); i += 2) {
            std::string byte_hex_str = hex_values_str.substr(i, 2);
            try { 
                unsigned long byte_val_ul = std::stoul(byte_hex_str, nullptr, 16);
                if (byte_val_ul > 0xFF) throw std::out_of_range("byte value exceeds 0xFF");
                bytes_to_write_to_memory.push_back(static_cast<unsigned char>(byte_val_ul)); 
            } 
            catch (const std::exception& e) { std::cout << "** the target address is not valid (invalid hex char in string)." << std::endl; return; }
        }
        if (bytes_to_write_to_memory.empty() && !hex_values_str.empty()){ // Should be caught by stoul errors
             std::cout << "** the target address is not valid (hex string parsing failed)." << std::endl; return;
        }
        
        // Check validity of the memory range to be patched by peeking first and last byte's word
        if (!bytes_to_write_to_memory.empty() && child_pid_ > 0) {
            errno = 0;
            peek_text(start_patch_addr); // Check readability of the start address
            if (errno != 0) { std::cout << "** the target address is not valid." << std::endl; return; }
            if (bytes_to_write_to_memory.size() > 1) { // If patching more than one byte
                errno = 0;
                peek_text(start_patch_addr + bytes_to_write_to_memory.size() - 1); // Check readability of the end address
                 if (errno != 0) { std::cout << "** the target address is not valid." << std::endl; return; }
            }
        } else if (bytes_to_write_to_memory.empty()) { // Patching with empty string
            std::cout << "** patch memory at 0x" << std::hex << start_patch_addr << "." << std::dec << std::endl; // No-op success
            return;
        }

        // Perform the patch byte by byte
        for (size_t i = 0; i < bytes_to_write_to_memory.size(); ++i) {
            if (child_pid_ <=0 ) { // Check at each byte if child died
                std::cout << "** target program terminated during patch." << std::endl; return;
            }
            unsigned long long current_byte_addr_being_patched = start_patch_addr + i;
            unsigned char byte_value_for_patch = bytes_to_write_to_memory[i];

            // Update the 'original_data' snapshot of any breakpoint whose word-span covers this byte.
            // This ensures that if the BP is hit and its original instruction restored, it restores the *patched* byte.
            for (auto& bp_entry : breakpoints_map_) { // Iterate by reference to modify map values
                unsigned long long bp_start_address_in_map = bp_entry.first;
                // Check if current_byte_addr_being_patched falls within the 8-byte span of this breakpoint's original_data word
                if (current_byte_addr_being_patched >= bp_start_address_in_map && current_byte_addr_being_patched < bp_start_address_in_map + sizeof(long)) {
                    long modified_original_data_snapshot = bp_entry.second; // Get a copy of the original word for this BP
                    int offset_within_snapshot = current_byte_addr_being_patched - bp_start_address_in_map;
                    ((unsigned char*)&modified_original_data_snapshot)[offset_within_snapshot] = byte_value_for_patch;
                    breakpoints_map_[bp_start_address_in_map] = modified_original_data_snapshot; // Update the map
                }
            }

            // Write the patch to live memory.
            // If current_byte_addr_being_patched is the start of a breakpoint, the 0xCC is in memory.
            // The spec: "breakpoint should still exist, but the original instruction should be patched."
            // This means the *snapshot* (original_data) is patched. The 0xCC in memory should remain.
            if (breakpoints_map_.count(current_byte_addr_being_patched)) {
                // This address is the start of a breakpoint. The 0xCC is in memory.
                // Its original_data snapshot was updated above. Do not poke memory here to preserve 0xCC.
            } else {
                // This address is NOT the start of a breakpoint. Patch memory directly.
                unsigned long long word_aligned_addr_for_poke = current_byte_addr_being_patched & ~(sizeof(long)-1);
                int byte_offset_in_word_for_poke = current_byte_addr_being_patched % sizeof(long);

                errno = 0;
                long current_memory_word_val = peek_text(word_aligned_addr_for_poke);
                if (errno != 0 && current_memory_word_val == -1L) { // Read failed
                    std::cout << "** the target address is not valid (read failed during patch)." << std::endl;
                    // Atomicity of the whole patch string is not required by spec. Stop on first error.
                    return; 
                }

                ((unsigned char*)&current_memory_word_val)[byte_offset_in_word_for_poke] = byte_value_for_patch; // Modify the byte
                poke_text(word_aligned_addr_for_poke, current_memory_word_val); // Write back the modified word
                if (errno == ESRCH && child_pid_ > 0) { // Child died during poke
                     // poke_text already sets child_pid_ = -1 and program_loaded_ = false
                     std::cout << "** the target address is not valid (write failed during patch, child died)." << std::endl;
                     return;
                }
            }
        }
        // If loop completed and child is still alive
        if (child_pid_ > 0) { 
            std::cout << "** patch memory at 0x" << std::hex << start_patch_addr << "." << std::dec << std::endl;
        }
    }
};

// Main function: creates Debugger instance and starts it.
int main(int argc, char *argv[]) {
    Debugger sdb;
    if (argc > 1) { // If program path is given as argument
        sdb.run(argv[1]);
    } else { // Start debugger without an initial program
        sdb.run();
    }
    return 0;
}