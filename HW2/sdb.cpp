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
                     program_loaded_ = false; 
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
            if (program_loaded_) { 
                for (auto const& [addr, original_data_word_snapshot] : breakpoints_map_) {
                    if (child_pid_ <=0) break; 
                    errno = 0;
                    long current_word_in_mem = peek_text(addr); 
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
        child_pid_ = -1; program_loaded_ = false; 
        current_program_path_.clear(); user_program_path_display_.clear();
        entry_point_from_elf_ = 0; actual_loaded_entry_point_ = 0; base_address_ = 0; load_offset_ = 0;
        text_segment_elf_va_ = 0; text_segment_size_ = 0; text_segment_start_ = 0;
        was_stopped_at_breakpoint_addr_ = 0; status_ = 0;
        breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); next_breakpoint_id_ = 0;
        executable_regions_.clear(); in_syscall_entry_ = true; 
        is_pie_or_dyn_cached_ = false;
    }
    
    long peek_text(unsigned long long addr) {
        if (child_pid_ <= 0) return -1L; 
        errno = 0;
        long data = ptrace(PTRACE_PEEKTEXT, child_pid_, (void*)addr, nullptr);
        if (errno != 0) { 
            if (errno == ESRCH && program_loaded_) { 
                program_loaded_ = false; 
                child_pid_ = -1;
            }
            return -1L; 
        }
        return data;
    }

    void poke_text(unsigned long long addr, long data) {
        if (child_pid_ <= 0) return; 
        errno = 0;
        if (ptrace(PTRACE_POKETEXT, child_pid_, (void*)addr, (void*)data) < 0) {
            if (errno == ESRCH && program_loaded_) { 
                program_loaded_ = false; 
                child_pid_ = -1;
            }
        }
    }

    void get_registers() {
        if (child_pid_ <= 0 || !program_loaded_ ) return; 
        if (ptrace(PTRACE_GETREGS, child_pid_, nullptr, &regs_) < 0) {
            if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
        }
    }

    void set_registers() {
        if (child_pid_ <= 0 || !program_loaded_) return;
        if (ptrace(PTRACE_SETREGS, child_pid_, nullptr, &regs_) < 0) {
            if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
        }
    }
    
    bool is_address_in_executable_region(unsigned long long addr) {
        if (text_segment_start_ != 0 && text_segment_size_ != 0) {
            if (addr >= text_segment_start_ && addr < text_segment_start_ + text_segment_size_) {
                return true;
            }
        }
        for (const auto& region : executable_regions_) {
            if (addr >= region.first && addr < region.second) {
                return true;
            }
        }
        return false;
    }

    void parse_elf_and_get_abs_entry(const char* program_file_path) {
        std::ifstream elf_file(program_file_path, std::ios::binary);
        if (!elf_file) { 
            text_segment_elf_va_ = 0; text_segment_size_ = 0; entry_point_from_elf_ = 0; 
            is_pie_or_dyn_cached_ = false; 
            return; 
        }

        Elf64_Ehdr ehdr;
        elf_file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
        if (elf_file.gcount() != static_cast<long>(sizeof(ehdr)) || 
            !(ehdr.e_ident[EI_MAG0] == ELFMAG0 && ehdr.e_ident[EI_MAG1] == ELFMAG1 &&
              ehdr.e_ident[EI_MAG2] == ELFMAG2 && ehdr.e_ident[EI_MAG3] == ELFMAG3)) { 
            text_segment_elf_va_ = 0; text_segment_size_ = 0; entry_point_from_elf_ = 0; 
            is_pie_or_dyn_cached_ = false;
            elf_file.close();
            return; 
        }
        
        entry_point_from_elf_ = ehdr.e_entry; 
        is_pie_or_dyn_cached_ = (ehdr.e_type == ET_DYN);

        text_segment_elf_va_ = 0;
        text_segment_size_ = 0;

        if (ehdr.e_shoff != 0 && ehdr.e_shstrndx != SHN_UNDEF && ehdr.e_shstrndx < ehdr.e_shnum) {
            elf_file.seekg(ehdr.e_shoff, std::ios::beg);
            std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
            elf_file.read(reinterpret_cast<char*>(shdrs.data()), ehdr.e_shnum * sizeof(Elf64_Shdr));

            if (elf_file.gcount() == static_cast<long>(ehdr.e_shnum * sizeof(Elf64_Shdr)) &&
                shdrs[ehdr.e_shstrndx].sh_size > 0 && ehdr.e_shstrndx < shdrs.size() && shdrs[ehdr.e_shstrndx].sh_type == SHT_STRTAB) { 
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
        elf_file.close(); 
        
        base_address_ = 0; 
        std::string maps_path = "/proc/" + std::to_string(child_pid_) + "/maps";
        std::ifstream maps_file(maps_path);
        std::string line_map_parser; 
        std::string proc_exe_path; 
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
                    if(map_offset == 0){ 
                        unsigned long long start_addr_map_segment = hex_to_ullong(addr_range_map.substr(0, addr_range_map.find('-')));
                        if(lowest_map_start_addr_for_exe == -1ULL || start_addr_map_segment < lowest_map_start_addr_for_exe){
                            lowest_map_start_addr_for_exe = start_addr_map_segment;
                        }
                    }
                } catch(...) { /* ignore parsing errors */ }
            }
        }
        if (lowest_map_start_addr_for_exe != -1ULL) base_address_ = lowest_map_start_addr_for_exe;
        maps_file.close();

        if (is_pie_or_dyn_cached_) {
            actual_loaded_entry_point_ = base_address_ + entry_point_from_elf_;
            load_offset_ = base_address_; 
        } else { 
            actual_loaded_entry_point_ = entry_point_from_elf_;
            load_offset_ = 0; 
        }
        
        if (text_segment_elf_va_ != 0 && text_segment_size_ != 0) { 
             text_segment_start_ = text_segment_elf_va_ + load_offset_;
        } else if (actual_loaded_entry_point_ != 0) { 
             bool found_entry_region = false;
             std::ifstream maps_file_fallback(maps_path); 
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

                 if(path_matches_fb && perms_fb.find('x') != std::string::npos) { 
                     size_t hyphen_pos = range_fb.find('-');
                     if (hyphen_pos != std::string::npos) {
                         try {
                             unsigned long long region_start = hex_to_ullong(range_fb.substr(0, hyphen_pos));
                             unsigned long long region_end = hex_to_ullong(range_fb.substr(hyphen_pos + 1));
                             if (actual_loaded_entry_point_ >= region_start && actual_loaded_entry_point_ < region_end) {
                                 text_segment_start_ = region_start; 
                                 text_segment_size_ = region_end - region_start; 
                                 found_entry_region = true;
                                 break;
                             }
                         } catch (...) {/*continue*/}
                     }
                 }
             }
             maps_file_fallback.close();
             if (!found_entry_region) { 
                 text_segment_start_ = base_address_ != 0 ? base_address_ : (actual_loaded_entry_point_ & ~(0xFFFULL)); 
                 text_segment_size_ = 0x2000; 
             }
        } else { 
            text_segment_start_ = base_address_; 
            text_segment_size_ = 0; 
        }

        executable_regions_.clear();
        std::ifstream maps_file_exec_regions(maps_path); 
        std::string line_exec_regions; 
        while(std::getline(maps_file_exec_regions, line_exec_regions)) {
            std::stringstream ss_exec(line_exec_regions);
            std::string addr_range_exec, perms_exec, offset_exec_str, dev_exec, inode_exec_str, path_exec;
            ss_exec >> addr_range_exec >> perms_exec >> offset_exec_str >> dev_exec >> inode_exec_str;
            std::getline(ss_exec, path_exec); 
            if (!path_exec.empty() && path_exec.front() == ' ') path_exec.erase(0, path_exec.find_first_not_of(" "));
            
            if (perms_exec.find('x') != std::string::npos) { 
                bool is_target_binary_region = false;
                if (!path_exec.empty() && (path_exec == current_program_path_ || (!proc_exe_path.empty() && path_exec == proc_exe_path))) {
                    is_target_binary_region = true;
                }
                if (is_target_binary_region || 
                    (path_exec.empty() && perms_exec.find('x') != std::string::npos) || 
                    path_exec.find("[vdso]") != std::string::npos || 
                    path_exec.find("[vsyscall]") != std::string::npos ) {
                    size_t hyphen_pos_exec = addr_range_exec.find('-');
                    if (hyphen_pos_exec != std::string::npos) {
                        try {
                            executable_regions_.push_back({
                                hex_to_ullong(addr_range_exec.substr(0, hyphen_pos_exec)),
                                hex_to_ullong(addr_range_exec.substr(hyphen_pos_exec + 1))
                            });
                        } catch(...) { /* ignore parsing error */ }
                    }
                }
            }
        }
        maps_file_exec_regions.close();
    }

    void load_program_internal(char** argv_for_exec) {
        if (program_loaded_) { kill_program(); } 
        
        entry_point_from_elf_ = 0; actual_loaded_entry_point_ = 0; base_address_ = 0; load_offset_ = 0;
        text_segment_elf_va_ = 0; text_segment_size_ = 0; text_segment_start_ = 0; executable_regions_.clear();
        breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); next_breakpoint_id_ = 0; 
        is_pie_or_dyn_cached_ = false; was_stopped_at_breakpoint_addr_ = 0;
        status_ = 0; 
        in_syscall_entry_ = true; 
        memset(&regs_, 0, sizeof(regs_));

        user_program_path_display_ = argv_for_exec[0]; 

        char abs_program_path_buf[PATH_MAX];
        if (realpath(argv_for_exec[0], abs_program_path_buf) == NULL) {
            current_program_path_ = argv_for_exec[0]; 
        } else {
            current_program_path_ = abs_program_path_buf; 
        }
        
        child_pid_ = fork();
        if (child_pid_ < 0) { perror("** fork failed"); program_loaded_ = false; return; }

        if (child_pid_ == 0) { 
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) { perror("** ptrace(TRACEME) failed"); _exit(EXIT_FAILURE); }
            if (execvp(current_program_path_.c_str(), argv_for_exec) < 0) { perror("** execvp failed"); _exit(EXIT_FAILURE); }
        } else { 
            if (waitpid(child_pid_, &status_, 0) < 0) { perror("** waitpid failed"); program_loaded_ = false; child_pid_ = -1; return;}
            
            if (!WIFSTOPPED(status_)) { 
                std::cerr << "** Program '" << user_program_path_display_ << "' failed to start or exited/signaled immediately." << std::endl;
                child_pid_ = -1; program_loaded_ = false; return;
            }
            if (ptrace(PTRACE_SETOPTIONS, child_pid_, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) < 0) {
                 // perror("** ptrace(PTRACE_SETOPTIONS) failed"); 
            }
            
            program_loaded_ = true; 
            parse_elf_and_get_abs_entry(current_program_path_.c_str());

            if (actual_loaded_entry_point_ == 0 && entry_point_from_elf_ == 0 && base_address_ == 0) {
                std::string auxv_path = "/proc/" + std::to_string(child_pid_) + "/auxv";
                std::ifstream auxv_file(auxv_path, std::ios::binary);
                if (auxv_file) {
                    Elf64_auxv_t auxv_entry_struct; 
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
             if (actual_loaded_entry_point_ == 0) { 
                std::cerr << "** Could not determine entry point for " << user_program_path_display_ << std::endl;
                kill_program(); return;
            }
            
            get_registers(); 
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

                if (child_pid_ > 0) poke_text(actual_loaded_entry_point_, original_word_at_target_entry); 
                
                if (WIFSTOPPED(status_) && WSTOPSIG(status_) == SIGTRAP) {
                    get_registers();
                    if (regs_.rip == actual_loaded_entry_point_ + 1) { 
                        regs_.rip--; 
                        set_registers(); 
                    } else if (regs_.rip != actual_loaded_entry_point_){
                        regs_.rip = actual_loaded_entry_point_; 
                        set_registers();
                    }
                } else { 
                    std::cerr << "** Failed to stop at program entry point after continuing from linker." << std::endl;
                    if (WIFEXITED(status_) || WIFSIGNALED(status_)) handle_wait_status(); else kill_program();
                    return;
                }
            }
            
            get_registers(); 
            
            std::cout << "** program '" << user_program_path_display_ << "' loaded. entry point: 0x" << std::hex << actual_loaded_entry_point_ << "." << std::dec << std::endl;
            disassemble_instructions(regs_.rip, 5); 
            was_stopped_at_breakpoint_addr_ = 0; 
        }
    }
    
    void disassemble_instructions(unsigned long long start_address, int count) {
        if (!program_loaded_ || child_pid_ <= 0) return;

        if (!is_address_in_executable_region(start_address) && start_address !=0) {
             std::cout << "** the address is out of the range of the executable region." << std::endl;
             return;
        }

        const int MAX_INSTR_BYTES_PER_INS = 15; 
        std::vector<unsigned char> instruction_bytes_buffer; 
        instruction_bytes_buffer.reserve(MAX_INSTR_BYTES_PER_INS * count + MAX_INSTR_BYTES_PER_INS); 

        unsigned long long current_addr_for_mem_read = start_address;
        size_t target_bytes_to_read_for_disassembly = MAX_INSTR_BYTES_PER_INS * (count + 2); 

        for (size_t total_bytes_copied_to_buffer = 0; total_bytes_copied_to_buffer < target_bytes_to_read_for_disassembly; ) {
            if (child_pid_ <=0) break; 

            if (total_bytes_copied_to_buffer > 0 && !is_address_in_executable_region(current_addr_for_mem_read) && current_addr_for_mem_read != 0) {
                break;
            }
            
            long memory_word_data = peek_text(current_addr_for_mem_read); 
            if (errno != 0 && memory_word_data == -1L) { 
                if (total_bytes_copied_to_buffer == 0 && !is_address_in_executable_region(start_address)) {
                }
                break; 
            }

            for (size_t byte_idx_in_word = 0; byte_idx_in_word < sizeof(long); ++byte_idx_in_word) {
                if (total_bytes_copied_to_buffer >= target_bytes_to_read_for_disassembly) break;
                
                unsigned long long actual_byte_address_in_memory = current_addr_for_mem_read + byte_idx_in_word;
                unsigned char byte_value_from_memory = (reinterpret_cast<unsigned char*>(&memory_word_data))[byte_idx_in_word];
                
                auto bp_iterator = breakpoints_map_.find(actual_byte_address_in_memory); 
                if (bp_iterator != breakpoints_map_.end()) { 
                    instruction_bytes_buffer.push_back((unsigned char)(bp_iterator->second & 0xFF)); 
                } else {
                    instruction_bytes_buffer.push_back(byte_value_from_memory);
                }
                total_bytes_copied_to_buffer++;
            }
            current_addr_for_mem_read += sizeof(long); 
        }

        if (instruction_bytes_buffer.empty()) {
            if (is_address_in_executable_region(start_address)) { 
                 std::cout << "** failed to read instructions at 0x" << std::hex << start_address << std::dec << "." << std::endl;
            } 
            return;
        }

        cs_insn *capstone_insn_array; 
        size_t num_insns_disassembled_by_capstone = cs_disasm(capstone_handle_, 
                                                            instruction_bytes_buffer.data(), 
                                                            instruction_bytes_buffer.size(), 
                                                            start_address, 
                                                            0, 
                                                            &capstone_insn_array); 

        std::cout << std::left; 

        size_t instructions_displayed_count = 0;
        bool oor_message_already_printed = false;
        unsigned long long address_after_last_displayed_instruction = start_address;

        if (num_insns_disassembled_by_capstone > 0) {
            for (size_t i = 0; i < num_insns_disassembled_by_capstone && instructions_displayed_count < static_cast<size_t>(count); ++i) {
                if (!is_address_in_executable_region(capstone_insn_array[i].address) && capstone_insn_array[i].address !=0 ) {
                    if (instructions_displayed_count > 0) { 
                         std::cout << "** the address is out of the range of the executable region." << std::endl;
                         oor_message_already_printed = true;
                    }
                    break; 
                }

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
            
            cs_free(capstone_insn_array, num_insns_disassembled_by_capstone); 
            
            if (instructions_displayed_count < static_cast<size_t>(count) && !oor_message_already_printed) {
                if (instructions_displayed_count > 0 || num_insns_disassembled_by_capstone == 0) { 
                     if (!is_address_in_executable_region(address_after_last_displayed_instruction) && address_after_last_displayed_instruction != 0 && address_after_last_displayed_instruction != start_address) {
                        std::cout << "** the address is out of the range of the executable region." << std::endl;
                     }
                }
            }
        } else { 
            if (is_address_in_executable_region(start_address) && !instruction_bytes_buffer.empty()){
            }
        }
        std::cout << std::right << std::flush; 
    }

    void handle_wait_status() { 
        if (child_pid_ <= 0 && !(WIFEXITED(status_) || WIFSIGNALED(status_))) { 
            return; 
        }

        if (WIFEXITED(status_)) {
            std::cout << "** the target program terminated." << std::endl;
            program_loaded_ = false; child_pid_ = -1; was_stopped_at_breakpoint_addr_ = 0; 
            breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); text_segment_elf_va_ = 0; text_segment_size_ = 0;
            executable_regions_.clear(); next_breakpoint_id_ = 0; load_offset_ = 0;
            actual_loaded_entry_point_ = 0; base_address_ = 0; entry_point_from_elf_ = 0;
            text_segment_start_ = 0; in_syscall_entry_ = true; 
            return;
        } else if (WIFSIGNALED(status_)) {
            std::cout << "** the target program terminated by signal " << strsignal(WTERMSIG(status_)) << "." << std::endl;
            program_loaded_ = false; child_pid_ = -1; was_stopped_at_breakpoint_addr_ = 0; 
            breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); text_segment_elf_va_ = 0; text_segment_size_ = 0;
            executable_regions_.clear(); next_breakpoint_id_ = 0; load_offset_ = 0;
            actual_loaded_entry_point_ = 0; base_address_ = 0; entry_point_from_elf_ = 0;
            text_segment_start_ = 0; in_syscall_entry_ = true; 
            return;
        }
        else if (WIFSTOPPED(status_)) {
            get_registers(); 
            
            if (child_pid_ <= 0) { 
                 if (program_loaded_) { program_loaded_ = false; } 
                 was_stopped_at_breakpoint_addr_ = 0; 
                 return;
            }

            bool event_handled_and_disassembled = false;
            unsigned long long rip_as_reported_by_kernel = regs_.rip; 
            was_stopped_at_breakpoint_addr_ = 0; 

            int stop_signal = WSTOPSIG(status_);

            // Priority 1: Syscall event from PTRACE_O_TRACESYSGOOD
            if (stop_signal == (SIGTRAP | 0x80)) {
                unsigned long long syscall_instruction_address = regs_.rip;
                if (regs_.rip >= 2) { syscall_instruction_address = regs_.rip - 2; }

                long syscall_number = regs_.orig_rax;
                long syscall_return_value = regs_.rax;

                if (in_syscall_entry_) {
                    std::cout << "** enter a syscall(" << std::dec << syscall_number << ") at 0x" << std::hex << syscall_instruction_address << "." << std::dec << std::endl;
                    in_syscall_entry_ = false;
                } else {
                    std::cout << "** leave a syscall(" << std::dec << syscall_number << ") = " << std::dec << syscall_return_value;
                    std::cout << " at 0x" << std::hex << syscall_instruction_address << "." << std::dec << std::endl;
                    in_syscall_entry_ = true;
                }
                disassemble_instructions(syscall_instruction_address, 5);
                event_handled_and_disassembled = true;
            }
            // Priority 2: Plain SIGTRAP (could be breakpoint, single-step, or syscall fallback)
            else if (stop_signal == SIGTRAP) {
                unsigned long long potential_bp_addr_from_int3 = rip_as_reported_by_kernel - 1;
                auto bp_iter_from_int3 = breakpoints_map_.find(potential_bp_addr_from_int3);
                auto bp_iter_direct_land = breakpoints_map_.find(rip_as_reported_by_kernel);

                if (bp_iter_from_int3 != breakpoints_map_.end()) { // Breakpoint hit (INT3)
                    regs_.rip = potential_bp_addr_from_int3; 
                    set_registers();        
                    std::cout << "** hit a breakpoint at 0x" << std::hex << regs_.rip << "." << std::dec << std::endl;
                    poke_text(regs_.rip, bp_iter_from_int3->second); 
                    was_stopped_at_breakpoint_addr_ = regs_.rip; 
                    disassemble_instructions(regs_.rip, 5);
                    event_handled_and_disassembled = true;
                } else if (bp_iter_direct_land != breakpoints_map_.end()) { // Single-step landed on an active BP
                    std::cout << "** hit a breakpoint at 0x" << std::hex << regs_.rip << "." << std::dec << std::endl;
                    poke_text(regs_.rip, bp_iter_direct_land->second); 
                    was_stopped_at_breakpoint_addr_ = regs_.rip;    
                    disassemble_instructions(regs_.rip, 5);
                    event_handled_and_disassembled = true;
                }
                // Fallback for PTRACE_SYSCALL command if TRACESYSGOOD was not effective
                else if (current_command_ == "syscall") { 
                    unsigned long long syscall_instruction_address = regs_.rip;
                    if (regs_.rip >= 2) { syscall_instruction_address = regs_.rip - 2; }

                    long syscall_number = regs_.orig_rax;
                    long syscall_return_value = regs_.rax;

                    if (in_syscall_entry_) {
                        std::cout << "** enter a syscall(" << std::dec << syscall_number << ") at 0x" << std::hex << syscall_instruction_address << "." << std::dec << std::endl;
                        in_syscall_entry_ = false;
                    } else {
                        std::cout << "** leave a syscall(" << std::dec << syscall_number << ") = " << std::dec << syscall_return_value;
                        std::cout << " at 0x" << std::hex << syscall_instruction_address << "." << std::dec << std::endl;
                        in_syscall_entry_ = true;
                    }
                    disassemble_instructions(syscall_instruction_address, 5);
                    event_handled_and_disassembled = true;
                }
                // If plain SIGTRAP and not handled above, it's likely a single-step completion.
                // It will fall through to the default disassembly.
            }
            // Priority 3: Other signals like SIGWINCH
            else if (stop_signal == SIGWINCH) { 
                if (program_loaded_ && child_pid_ > 0) {
                    ptrace(PTRACE_CONT, child_pid_, nullptr, (void*)((long)stop_signal)); 
                    if (waitpid(child_pid_, &status_, 0) < 0 ) { 
                        if(program_loaded_ && child_pid_ > 0) { child_pid_ = -1; program_loaded_ = false;} 
                    }
                    if (child_pid_ > 0 && program_loaded_) handle_wait_status(); 
                    return; 
                }
            }
            // Priority 4: Other stop signals
            else { 
                if (program_loaded_ && child_pid_ > 0) { 
                    std::cout << "** Child stopped by signal " << strsignal(stop_signal) << " (SIG=" << stop_signal << ")" << std::endl;
                }
            }

            // Default disassembly if not specifically handled above and program is still running
            if (!event_handled_and_disassembled && program_loaded_ && child_pid_ > 0) {
                disassemble_instructions(rip_as_reported_by_kernel, 5);
            }
        }
    }

    void step_instruction() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        
        get_registers();
        unsigned long long rip_before_step = regs_.rip;
        bool stepping_from_active_restored_bp = (was_stopped_at_breakpoint_addr_ == rip_before_step && was_stopped_at_breakpoint_addr_ != 0);
        
        if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) { 
            if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; } 
            return; 
        }
        if (waitpid(child_pid_, &status_, 0) < 0) { 
            if (program_loaded_ && child_pid_ > 0) { child_pid_ = -1; program_loaded_ = false; } 
            return;
        }

        if (stepping_from_active_restored_bp) { 
            auto bp_iterator = breakpoints_map_.find(rip_before_step); 
            if (bp_iterator != breakpoints_map_.end()) { 
                if (child_pid_ > 0 && program_loaded_) { 
                    long rearm_breakpoint_word = (bp_iterator->second & ~0xFFL) | 0xCC; 
                    poke_text(rip_before_step, rearm_breakpoint_word);
                }
            }
        }
        handle_wait_status(); 
    }

    void continue_execution() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        
        get_registers();
        unsigned long long rip_at_continue_start = regs_.rip;

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

            if (child_pid_ > 0 && program_loaded_) { 
                auto bp_iterator = breakpoints_map_.find(rip_at_continue_start);
                if (bp_iterator != breakpoints_map_.end()) { 
                    long rearm_breakpoint_word = (bp_iterator->second & ~0xFFL) | 0xCC;
                    poke_text(rip_at_continue_start, rearm_breakpoint_word);
                }
            } else { 
                status_ = temp_status_after_single_step; 
                handle_wait_status(); 
                return; 
            }

            if (WIFEXITED(temp_status_after_single_step) || WIFSIGNALED(temp_status_after_single_step)) {
                status_ = temp_status_after_single_step; 
                handle_wait_status(); 
                return; 
            }
            status_ = temp_status_after_single_step; 
        }
        
        if (child_pid_ > 0 && program_loaded_) { 
            if (ptrace(PTRACE_CONT, child_pid_, nullptr, nullptr) < 0) { 
                if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
                return; 
            }
            if (waitpid(child_pid_, &status_, 0) < 0) {
                if (program_loaded_ && child_pid_ > 0) {child_pid_ = -1; program_loaded_ = false;}
                return;
            }
            handle_wait_status(); 
        }
    }

    void handle_syscall_command() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        get_registers();
        unsigned long long rip_at_cmd_start = regs_.rip;
        
        if (was_stopped_at_breakpoint_addr_ == rip_at_cmd_start && was_stopped_at_breakpoint_addr_ != 0) {
            if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) { 
                if (errno == ESRCH) {program_loaded_=false; child_pid_=-1;} return; 
            }
            int temp_status;
            if (waitpid(child_pid_, &temp_status, 0) < 0) { 
                if (program_loaded_&&child_pid_>0) {program_loaded_=false; child_pid_=-1;} return;
            }
            
            if (child_pid_ > 0 && program_loaded_) {
                auto bp_it = breakpoints_map_.find(rip_at_cmd_start);
                if (bp_it != breakpoints_map_.end()) {
                    long rearm_word = (bp_it->second & ~0xFFL) | 0xCC;
                    poke_text(rip_at_cmd_start, rearm_word);
                }
            } else { status_ = temp_status; handle_wait_status(); return; }

            if (WIFEXITED(temp_status) || WIFSIGNALED(temp_status) ) {
                status_ = temp_status; handle_wait_status(); return;
            }
            status_ = temp_status; 
            if (WIFSTOPPED(status_)) { // Check if the single step hit something significant
                 int stop_sig_after_step = WSTOPSIG(status_);
                 if (stop_sig_after_step == (SIGTRAP | 0x80)) { // Hit a syscall immediately
                     handle_wait_status(); // Process it as a syscall
                     return;
                 } else if (stop_sig_after_step == SIGTRAP) { // Could be another breakpoint
                     get_registers(); 
                     unsigned long long current_rip_after_step = regs_.rip;
                     bool hit_another_bp = breakpoints_map_.count(current_rip_after_step -1) || breakpoints_map_.count(current_rip_after_step);
                     if(hit_another_bp) {
                        handle_wait_status(); 
                        return; 
                     }
                     // If not another BP, it was just a single step, proceed to PTRACE_SYSCALL
                 }
                 // If other signal, let PTRACE_SYSCALL proceed, or handle_wait_status will catch it.
            }
        }
        
        if (child_pid_ > 0 && program_loaded_) {
            if (ptrace(PTRACE_SYSCALL, child_pid_, nullptr, nullptr) < 0) {
                if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
                return;
            }
            if (waitpid(child_pid_, &status_, 0) < 0) {
                if(program_loaded_ && child_pid_ > 0) {child_pid_ = -1; program_loaded_ = false;} 
                return;
            }
            handle_wait_status(); 
        }
    }

    void print_registers() {
        if (!program_loaded_ || child_pid_ <=0) { return; }
        if (ptrace(PTRACE_GETREGS, child_pid_, nullptr, &regs_) < 0) {
            if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; } 
            return;
        }

        std::ios_base::fmtflags original_flags = std::cout.flags(); 
        std::cout << std::hex << std::setfill('0');
        std::cout << "$rax 0x" << std::setw(16) << regs_.rax << "    $rbx 0x" << std::setw(16) << regs_.rbx << "    $rcx 0x" << std::setw(16) << regs_.rcx << std::endl;
        std::cout << "$rdx 0x" << std::setw(16) << regs_.rdx << "    $rsi 0x" << std::setw(16) << regs_.rsi << "    $rdi 0x" << std::setw(16) << regs_.rdi << std::endl;
        std::cout << "$rbp 0x" << std::setw(16) << regs_.rbp << "    $rsp 0x" << std::setw(16) << regs_.rsp << "    $r8  0x" << std::setw(16) << regs_.r8  << std::endl;
        std::cout << "$r9  0x" << std::setw(16) << regs_.r9  << "    $r10 0x" << std::setw(16) << regs_.r10 << "    $r11 0x" << std::setw(16) << regs_.r11 << std::endl;
        std::cout << "$r12 0x" << std::setw(16) << regs_.r12 << "    $r13 0x" << std::setw(16) << regs_.r13 << "    $r14 0x" << std::setw(16) << regs_.r14 << std::endl;
        std::cout << "$r15 0x" << std::setw(16) << regs_.r15 << "    $rip 0x" << std::setw(16) << regs_.rip << "    $eflags 0x" << std::setw(16) << regs_.eflags << std::endl;
        std::cout.flags(original_flags); 
    }

    void set_breakpoint_common(unsigned long long addr, bool is_rva_command) {
        if (!program_loaded_ || child_pid_ <= 0) { return; }
        
        bool is_valid_address_for_breakpoint = false;
        if (text_segment_start_ != 0 && text_segment_size_ != 0) { 
            if (addr >= text_segment_start_ && addr < text_segment_start_ + text_segment_size_) {
                is_valid_address_for_breakpoint = true;
            }
        }
        if (!is_valid_address_for_breakpoint) { 
            for(const auto& region : executable_regions_){
                if(addr >= region.first && addr < region.second){
                    is_valid_address_for_breakpoint = true;
                    break;
                }
            }
        }
        if (!is_valid_address_for_breakpoint && addr != 0 && executable_regions_.empty() && text_segment_size_ == 0) {
            errno = 0;
            peek_text(addr); 
            if (errno == 0) is_valid_address_for_breakpoint = true; 
        }

        if (!is_valid_address_for_breakpoint) { 
            std::cout << "** the target address is not valid." << std::endl; return;
        }

        if (breakpoints_map_.count(addr)) { 
             std::cout << "** set a breakpoint at 0x" << std::hex << addr << "." << std::dec << std::endl; 
             return;
        }
        
        long original_memory_word = peek_text(addr); 
        if (errno != 0 && original_memory_word == -1L) { 
            std::cout << "** the target address is not valid." << std::endl; return;
        }
        
        breakpoints_map_[addr] = original_memory_word; 
        breakpoint_id_to_addr_[next_breakpoint_id_] = addr; 
        
        long breakpoint_word = (original_memory_word & ~0xFFL) | 0xCC; 
        poke_text(addr, breakpoint_word); 
        
        std::cout << "** set a breakpoint at 0x" << std::hex << addr << "." << std::dec << std::endl;
        next_breakpoint_id_++;
    }

    void set_breakpoint(const std::string& addr_str) {
        unsigned long long addr;
        try { addr = hex_to_ullong(addr_str); } 
        catch (const std::exception& e) { std::cout << "** the target address is not valid." << std::endl; return; }
        set_breakpoint_common(addr, false);
    }

    void set_breakpoint_rva(const std::string& offset_str) {
        unsigned long long offset;
        try { offset = hex_to_ullong(offset_str); } 
        catch (const std::exception& e) { std::cout << "** the target address is not valid." << std::endl; return; }
        
        unsigned long long addr = base_address_ + offset; 
        set_breakpoint_common(addr, true);
    }

    void info_breakpoints() {
        if (!program_loaded_) { return; } 
        std::vector<std::pair<int, unsigned long long>> active_breakpoints_for_display;
        for(const auto& id_addr_pair : breakpoint_id_to_addr_){
            if(breakpoints_map_.count(id_addr_pair.second)){ 
                active_breakpoints_for_display.push_back({id_addr_pair.first, id_addr_pair.second});
            }
        }
        std::sort(active_breakpoints_for_display.begin(), active_breakpoints_for_display.end()); 

        if (active_breakpoints_for_display.empty()) { std::cout << "** no breakpoints." << std::endl; return; }

        std::cout << "Num     Address" << std::endl; 
        for (const auto& bp_info : active_breakpoints_for_display) {
            std::cout << std::left << std::setw(8) << bp_info.first 
                      << "0x" << std::hex << bp_info.second << std::dec << std::endl; 
        }
    }

    void delete_breakpoint(int id) {
        if (!program_loaded_ || child_pid_ <= 0) { return; }
        auto id_iterator = breakpoint_id_to_addr_.find(id);
        if (id_iterator == breakpoint_id_to_addr_.end()) { 
            std::cout << "** breakpoint " << id << " does not exist." << std::endl; return;
        }

        unsigned long long addr_to_delete = id_iterator->second;
        auto bp_data_iterator = breakpoints_map_.find(addr_to_delete);
        if (bp_data_iterator == breakpoints_map_.end()) { 
            std::cout << "** breakpoint " << id << " does not exist (internal error - map inconsistent)." << std::endl;
            breakpoint_id_to_addr_.erase(id_iterator); 
            return;
        }

        long original_word_snapshot_when_bp_set = bp_data_iterator->second; 
        
        if (child_pid_ > 0 && program_loaded_) { 
            errno = 0;
            long current_word_in_memory_at_bp = peek_text(addr_to_delete); 

            if (errno == 0) { 
                unsigned char original_first_byte_of_instruction = (unsigned char)(original_word_snapshot_when_bp_set & 0xFFL);
                long word_to_restore_to_memory = (current_word_in_memory_at_bp & ~0xFFL) | original_first_byte_of_instruction;
                poke_text(addr_to_delete, word_to_restore_to_memory);
            } else if (errno != ESRCH) { 
                poke_text(addr_to_delete, original_word_snapshot_when_bp_set);
            }
        }

        breakpoints_map_.erase(bp_data_iterator); 
        breakpoint_id_to_addr_.erase(id_iterator); 
        std::cout << "** delete breakpoint " << id << "." << std::endl;
    }

    void patch_memory(const std::string& addr_str, const std::string& hex_values_str) {
        if (!program_loaded_ || child_pid_ <= 0) { return; }
        unsigned long long start_patch_addr;
        try { start_patch_addr = hex_to_ullong(addr_str); } 
        catch (const std::exception& e) { std::cout << "** the target address is not valid." << std::endl; return; }

        if (hex_values_str.length() % 2 != 0 || hex_values_str.length() > 2048 || hex_values_str.empty()) {
            std::cout << "** the target address is not valid (invalid hex string format/length)." << std::endl; return;
        }

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
        if (bytes_to_write_to_memory.empty() && !hex_values_str.empty()){ 
             std::cout << "** the target address is not valid (hex string parsing failed)." << std::endl; return;
        }
        
        if (!bytes_to_write_to_memory.empty() && child_pid_ > 0) {
            errno = 0;
            peek_text(start_patch_addr); 
            if (errno != 0) { std::cout << "** the target address is not valid." << std::endl; return; }
            if (bytes_to_write_to_memory.size() > 1) { 
                errno = 0;
                peek_text(start_patch_addr + bytes_to_write_to_memory.size() - 1); 
                 if (errno != 0) { std::cout << "** the target address is not valid." << std::endl; return; }
            }
        } else if (bytes_to_write_to_memory.empty()) { 
            std::cout << "** patch memory at 0x" << std::hex << start_patch_addr << "." << std::dec << std::endl; 
            return;
        }

        for (size_t i = 0; i < bytes_to_write_to_memory.size(); ++i) {
            if (child_pid_ <=0 ) { 
                std::cout << "** target program terminated during patch." << std::endl; return;
            }
            unsigned long long current_byte_addr_being_patched = start_patch_addr + i;
            unsigned char byte_value_for_patch = bytes_to_write_to_memory[i];

            for (auto& bp_entry : breakpoints_map_) { 
                unsigned long long bp_start_address_in_map = bp_entry.first;
                if (current_byte_addr_being_patched >= bp_start_address_in_map && current_byte_addr_being_patched < bp_start_address_in_map + sizeof(long)) {
                    long modified_original_data_snapshot = bp_entry.second; 
                    int offset_within_snapshot = current_byte_addr_being_patched - bp_start_address_in_map;
                    ((unsigned char*)&modified_original_data_snapshot)[offset_within_snapshot] = byte_value_for_patch;
                    breakpoints_map_[bp_start_address_in_map] = modified_original_data_snapshot; 
                }
            }

            if (breakpoints_map_.count(current_byte_addr_being_patched)) {
            } else {
                unsigned long long word_aligned_addr_for_poke = current_byte_addr_being_patched & ~(sizeof(long)-1);
                int byte_offset_in_word_for_poke = current_byte_addr_being_patched % sizeof(long);

                errno = 0;
                long current_memory_word_val = peek_text(word_aligned_addr_for_poke);
                if (errno != 0 && current_memory_word_val == -1L) { 
                    std::cout << "** the target address is not valid (read failed during patch)." << std::endl;
                    return; 
                }

                ((unsigned char*)&current_memory_word_val)[byte_offset_in_word_for_poke] = byte_value_for_patch; 
                poke_text(word_aligned_addr_for_poke, current_memory_word_val); 
                if (errno == ESRCH && child_pid_ > 0) { 
                     std::cout << "** the target address is not valid (write failed during patch, child died)." << std::endl;
                     return;
                }
            }
        }
        if (child_pid_ > 0) { 
            std::cout << "** patch memory at 0x" << std::hex << start_patch_addr << "." << std::dec << std::endl;
        }
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