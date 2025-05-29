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

struct Breakpoint {
    int id;
    unsigned long long address;
    long original_data; 

    Breakpoint() : id(-1), address(0), original_data(0) {}

    Breakpoint(int i, unsigned long long addr, long orig_data)
        : id(i), address(addr), original_data(orig_data) {}
};


class Debugger {
private: 
    pid_t child_pid_;
    bool program_loaded_;
    std::string current_program_path_;      
    std::string user_program_path_display_; 
    unsigned long long entry_point_from_elf_; 
    unsigned long long actual_loaded_entry_point_; 
    unsigned long long base_address_;  
    unsigned long long load_offset_; 
    unsigned long long text_segment_elf_va_; 
    unsigned long long text_segment_size_;
    unsigned long long text_segment_start_; 
    unsigned long long was_stopped_at_breakpoint_addr_; 
    
    struct user_regs_struct regs_;
    int status_; 

    std::map<unsigned long long, long> breakpoints_map_; 
    std::map<int, unsigned long long> breakpoint_id_to_addr_; 
    int next_breakpoint_id_;

    csh capstone_handle_;
    std::vector<std::pair<unsigned long long, unsigned long long>> executable_regions_;
    
    bool in_syscall_entry_;
    std::string current_command_;
    bool is_pie_or_dyn_cached_;


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
        in_syscall_entry_(false),
        is_pie_or_dyn_cached_(false)
    {
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

    void run(const std::string& initial_program_path_arg = "") {
        if (setvbuf(stdin, nullptr, _IONBF, 0) != 0) { /* Non-critical error */ }

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
            if (program_loaded_ && WIFSTOPPED(status_)) { 
                // Program is loaded and stopped, ready for next command
            } else if (!program_loaded_) {
                // Program not loaded, or was terminated.
            } else if (WIFEXITED(status_) || WIFSIGNALED(status_)) { 
                // This case should be handled by handle_wait_status which then sets program_loaded_ = false
                // If we reach here and program_loaded_ is true, it means termination happened
                // and handle_wait_status might not have been the last thing called or it didn't reset.
                // The handle_wait_status will print termination and reset flags.
                // This condition check here is more of a safeguard.
                // The primary reset logic is at the end of handle_wait_status for termination.
            }
            
            std::cout << "(sdb) " << std::flush;
            if (!std::getline(std::cin, line)) { if (child_pid_ > 0) kill_program(); break;}


            std::vector<std::string> args = split_string(line, ' ');
            if (args.empty() || args[0].empty()) {
                continue;
            }

            current_command_ = args[0]; 

            if (current_command_ == "load") {
                if (child_pid_ > 0) kill_program(); 

                if (args.size() < 2) {
                    std::cerr << "** Usage: load [path to program]" << std::endl;
                } else {
                    user_program_path_display_ = args[1];
                    std::vector<char*> argv_vec;
                    char* loaded_prog_name_c_str = strdup(args[1].c_str());
                    if (!loaded_prog_name_c_str) { std::cerr << "** Memory allocation failed for loaded program name." << std::endl; continue;}
                    argv_vec.push_back(loaded_prog_name_c_str);
                    argv_vec.push_back(nullptr); 
                    
                    load_program_internal(argv_vec.data());

                    free(loaded_prog_name_c_str);
                }
            } else if (current_command_ == "exit" || current_command_ == "quit" || current_command_ == "q") {
                kill_program();
                break;
            }
            else if (!program_loaded_) {
                if (current_command_ == "si" || current_command_ == "cont" || current_command_ == "info" ||
                    current_command_ == "break" || current_command_ == "breakrva" || current_command_ == "delete" ||
                    current_command_ == "patch" || current_command_ == "syscall") {
                    std::cout << "** please load a program first." << std::endl;
                } else if (!current_command_.empty()){ 
                    std::cout << "** Unknown command: " << current_command_ << std::endl;
                }
            } else { 
                // Program is loaded and child_pid_ > 0 (or should be if not terminated)
                if (WIFEXITED(status_) || WIFSIGNALED(status_)) { // Check if program terminated before command
                     std::cout << "** the target program terminated." << std::endl;
                     program_loaded_ = false; child_pid_ = -1;
                     // Reset states related to a loaded program
                     breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); text_segment_elf_va_ = 0; text_segment_size_ = 0;
                     executable_regions_.clear(); next_breakpoint_id_ = 0; load_offset_ = 0;
                     actual_loaded_entry_point_ = 0; base_address_ = 0; entry_point_from_elf_ = 0;
                     was_stopped_at_breakpoint_addr_ = 0; text_segment_start_ = 0;
                     continue; // Go to next prompt
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

    void kill_program() {
        if (child_pid_ > 0) {
            // Detach and attempt to restore breakpoints before killing
            // This might fail if the process is already gone or in a weird state
            for (auto const& [addr, original_data_word] : breakpoints_map_) {
                if (child_pid_ <=0) break; 
                long current_word_val = ptrace(PTRACE_PEEKTEXT, child_pid_, (void*)addr, 0);
                if (errno == 0 && (current_word_val & 0xFF) == 0xCC) { 
                    // Only restore if 0xCC is present, to avoid corrupting unrelated changes
                    ptrace(PTRACE_POKETEXT, child_pid_, (void*)addr, (void*)original_data_word);
                } else if (errno == ESRCH) { // Child already gone
                    child_pid_ = -1; // Mark as gone
                    break;
                }
            }
            
            if (child_pid_ > 0) { // If still seems alive
                 ptrace(PTRACE_KILL, child_pid_, nullptr, nullptr); 
                 waitpid(child_pid_, nullptr, 0); // Reap the killed child
            }
        }
        // Reset all state variables
        child_pid_ = -1; program_loaded_ = false; 
        current_program_path_.clear(); user_program_path_display_.clear();
        entry_point_from_elf_ = 0; actual_loaded_entry_point_ = 0; base_address_ = 0; load_offset_ = 0;
        text_segment_elf_va_ = 0; text_segment_size_ = 0; text_segment_start_ = 0;
        was_stopped_at_breakpoint_addr_ = 0; status_ = 0;
        breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); next_breakpoint_id_ = 0;
        executable_regions_.clear(); in_syscall_entry_ = false; is_pie_or_dyn_cached_ = false;
    }
    
    long peek_text(unsigned long long addr) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKTEXT, child_pid_, (void*)addr, nullptr);
        if (errno != 0) { 
            if (errno == ESRCH && program_loaded_) { 
                // Child died unexpectedly
                program_loaded_ = false; 
                child_pid_ = -1;
                // No message here, will be handled by wait_status or command functions
            }
            return -1; 
        }
        return data;
    }

    void poke_text(unsigned long long addr, long data) {
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
        // Check primary .text segment first if available (and loaded correctly)
        if (text_segment_start_ != 0 && text_segment_size_ != 0) {
            if (addr >= text_segment_start_ && addr < text_segment_start_ + text_segment_size_) {
                return true;
            }
        }
        // Fallback to general executable regions from /proc/pid/maps for more coverage (e.g. other exec sections)
        for (const auto& region : executable_regions_) {
            if (addr >= region.first && addr < region.second) {
                return true;
            }
        }
        return false;
    }

    void parse_elf_and_get_abs_entry(const char* program_file_path) {
        std::ifstream elf_file(program_file_path, std::ios::binary);
        if (!elf_file) { text_segment_elf_va_ = 0; entry_point_from_elf_ = 0; return; }

        Elf64_Ehdr ehdr;
        elf_file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
        if (elf_file.gcount() != static_cast<long>(sizeof(ehdr)) || 
            !(ehdr.e_ident[EI_MAG0] == ELFMAG0 && ehdr.e_ident[EI_MAG1] == ELFMAG1 &&
              ehdr.e_ident[EI_MAG2] == ELFMAG2 && ehdr.e_ident[EI_MAG3] == ELFMAG3)) { 
            text_segment_elf_va_ = 0; entry_point_from_elf_ = 0; return; 
        }
        
        entry_point_from_elf_ = ehdr.e_entry; 
        is_pie_or_dyn_cached_ = (ehdr.e_type == ET_DYN);

        text_segment_elf_va_ = 0;
        text_segment_size_ = 0;

        if (ehdr.e_shoff == 0 || ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= ehdr.e_shnum) {
             // No section header string table, try to find .text by flags if possible (more complex)
             // For this assignment, relying on .text name is usually sufficient.
        } else {
            elf_file.seekg(ehdr.e_shoff, std::ios::beg);
            std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
            elf_file.read(reinterpret_cast<char*>(shdrs.data()), ehdr.e_shnum * sizeof(Elf64_Shdr));
            if (elf_file.gcount() == static_cast<long>(ehdr.e_shnum * sizeof(Elf64_Shdr))) {
                if (shdrs[ehdr.e_shstrndx].sh_size > 0 && ehdr.e_shstrndx < shdrs.size()) { 
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
        }
        
        base_address_ = 0; 
        std::string maps_path_local = "/proc/" + std::to_string(child_pid_) + "/maps";
        std::ifstream maps_file_local(maps_path_local);
        std::string line_local_map_parser; 
        std::string proc_exe_path_local;
        char exe_path_buf_local[PATH_MAX + 1] = {0}; 
        std::string symlink_path_local = "/proc/" + std::to_string(child_pid_) + "/exe";
        ssize_t len_local = readlink(symlink_path_local.c_str(), exe_path_buf_local, PATH_MAX);
        if (len_local != -1) {
            exe_path_buf_local[len_local] = '\0'; 
            proc_exe_path_local = std::string(exe_path_buf_local);
        }

        unsigned long long temp_potential_base = -1ULL; // Use -1ULL for uninitialized state
        while(std::getline(maps_file_local, line_local_map_parser)){ 
            std::stringstream ss_local(line_local_map_parser);
            std::string addr_range_local, perms_local, offset_str_local, dev_local, inode_str_local, pathname_local;
            ss_local >> addr_range_local >> perms_local >> offset_str_local >> dev_local >> inode_str_local;
            std::getline(ss_local, pathname_local); // Read the rest of the line
            if (!pathname_local.empty() && pathname_local.front() == ' ') pathname_local.erase(0, pathname_local.find_first_not_of(" "));
            // No need to strip trailing spaces for path comparison usually, but good for consistency if needed.

            bool path_matches_local = false;
            if (!pathname_local.empty() && (pathname_local == current_program_path_ || (!proc_exe_path_local.empty() && pathname_local == proc_exe_path_local) ) ) {
                path_matches_local = true;
            }

            if(path_matches_local){
                try {
                    unsigned long long map_offset_local = hex_to_ullong(offset_str_local);
                    if(map_offset_local == 0){ // First segment of the executable mapping
                        unsigned long long start_addr_local = hex_to_ullong(addr_range_local.substr(0, addr_range_local.find('-')));
                        if(temp_potential_base == -1ULL || start_addr_local < temp_potential_base){
                            temp_potential_base = start_addr_local;
                        }
                    }
                } catch(...) { /* ignore parsing errors for this map line */ }
            }
        }
        if (temp_potential_base != -1ULL) base_address_ = temp_potential_base;

        if (is_pie_or_dyn_cached_) {
            if (base_address_ == 0 && entry_point_from_elf_ != 0 && text_segment_elf_va_ != 0) { 
                 // If base_address_ couldn't be found from maps for a PIE, it's an issue.
                 // However, some PIEs might have e_entry as 0 and rely purely on dynamic linker.
                 // The spec implies we need to find the *target binary's* entry point.
            }
            actual_loaded_entry_point_ = base_address_ + entry_point_from_elf_;
            load_offset_ = base_address_; 
        } else { 
            actual_loaded_entry_point_ = entry_point_from_elf_;
            load_offset_ = 0; 
            if (base_address_ == 0 && actual_loaded_entry_point_ != 0) {
                 // For non-PIE, base_address_ might be 0 if not found, or it could be the fixed load addr (e.g. 0x400000)
                 // If text_segment_elf_va_ is e.g. 0x401000, then base_address should be 0 for breakrva to work relative to 0.
                 // Or, base_address_ should be that fixed load address. The most consistent is that
                 // base_address_ is the actual load address of the segment with offset 0 in maps.
                 // If non-PIE, entry_point_from_elf_ is absolute. load_offset_ is 0.
                 // base_address_ (for breakrva) should be the start of the ELF image in memory.
            }
        }
        
        if (text_segment_elf_va_ != 0) { 
            text_segment_start_ = text_segment_elf_va_ + (is_pie_or_dyn_cached_ ? base_address_ : 0);
        } else if (actual_loaded_entry_point_ != 0) { 
            // Fallback if .text section couldn't be parsed by name
            text_segment_start_ = actual_loaded_entry_point_ & ~(0xFFFULL) ; // Align to page, rough estimate
            text_segment_size_ = 0x2000; // A guess for size
        } else {
            text_segment_start_ = base_address_; // If entry is 0, text might start at base
        }


        executable_regions_.clear();
        std::ifstream maps_file_exec("/proc/" + std::to_string(child_pid_) + "/maps");
        std::string line_for_exec_regions; 
        while(std::getline(maps_file_exec, line_for_exec_regions)) {
            std::stringstream ss_exec(line_for_exec_regions);
            std::string addr_range_exec, perms_exec, offset_exec, dev_exec, inode_exec, path_exec;
            ss_exec >> addr_range_exec >> perms_exec >> offset_exec >> dev_exec >> inode_exec;
            std::getline(ss_exec, path_exec); // Read rest for path
            if (!path_exec.empty() && path_exec.front() == ' ') path_exec.erase(0, path_exec.find_first_not_of(" "));
            
            // We only care about executable regions of the main program for disassembly validity in spec.
            // However, the spec for patch also says "valid address", which might include writable data regions.
            // For "executable region" in disassembly, we need to be more specific.
            // The spec for disassembling says "address of the 5 instructions should be within the range of the executable region."
            // This typically refers to regions with 'x' perm from the target binary.
            if (perms_exec.find('x') != std::string::npos) {
                 // For PIE, only add regions belonging to the main executable.
                 // For non-PIE, could also be more specific.
                 // The `is_address_in_executable_region` uses this list.
                bool region_belongs_to_target = false;
                if (!path_exec.empty() && (path_exec == current_program_path_ || (!proc_exe_path_local.empty() && path_exec == proc_exe_path_local))) {
                    region_belongs_to_target = true;
                } else if (path_exec.empty() && perms_exec.find('x') != std::string::npos) {
                    // Anon memory could be JIT code. For extra example.
                    // region_belongs_to_target = true; 
                }


                if(region_belongs_to_target || path_exec.find("[vdso]") != std::string::npos || path_exec.find("[vsyscall]") != std::string::npos ) { // Also consider VDSO for syscall example.
                                                                                                                                                    // For "anon" example, it mmap an anon region.
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
        // If text_segment_start_ and size are valid, make sure it's in executable_regions_ or use it primarily
        if (text_segment_start_ != 0 && text_segment_size_ != 0) {
            bool text_segment_already_added = false;
            for(const auto& region : executable_regions_) {
                if (region.first == text_segment_start_ && region.second == text_segment_start_ + text_segment_size_) {
                    text_segment_already_added = true;
                    break;
                }
            }
            if (!text_segment_already_added) {
                 // It's possible maps parsing is different; text_segment_start_ from ELF is primary.
                 // But for general executable region check, maps is more comprehensive.
                 // The is_address_in_executable_region checks both.
            }
        }
    }


    void load_program_internal(char** argv_for_exec) {
        if (program_loaded_) { kill_program(); } // Kill previous program if any
        
        // Reset all state
        entry_point_from_elf_ = 0; actual_loaded_entry_point_ = 0; base_address_ = 0; load_offset_ = 0;
        text_segment_elf_va_ = 0; text_segment_size_ = 0; text_segment_start_ = 0; executable_regions_.clear();
        breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); next_breakpoint_id_ = 0; 
        is_pie_or_dyn_cached_ = false; was_stopped_at_breakpoint_addr_ = 0;
        status_ = 0; 
        memset(&regs_, 0, sizeof(regs_));


        user_program_path_display_ = argv_for_exec[0];

        char abs_program_path_buf[PATH_MAX];
        if (realpath(argv_for_exec[0], abs_program_path_buf) == NULL) {
            // realpath fails (e.g. file not found yet, execvp will handle)
            current_program_path_ = argv_for_exec[0]; 
        } else {
            current_program_path_ = abs_program_path_buf; 
        }
        
        child_pid_ = fork();
        if (child_pid_ < 0) { perror("** fork failed"); program_loaded_ = false; return; }

        if (child_pid_ == 0) { // Child process
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) { perror("** ptrace(TRACEME) failed"); _exit(EXIT_FAILURE); }
            // Stop child so parent can set options before exec
            // raise(SIGSTOP); // Or parent can wait for the implicit stop after exec
            if (execvp(current_program_path_.c_str(), argv_for_exec) < 0) { perror("** execvp failed"); _exit(EXIT_FAILURE); }
        } else { // Parent process
            if (waitpid(child_pid_, &status_, 0) < 0) { perror("** waitpid failed"); program_loaded_ = false; child_pid_ = -1; return;}
            
            if (!WIFSTOPPED(status_)) { 
                std::cerr << "** Program '" << user_program_path_display_ << "' failed to start or exited/signaled immediately." << std::endl;
                child_pid_ = -1; program_loaded_ = false; return;
            }
            // Set options after the first stop (which is due to PTRACE_TRACEME or implicit stop after exec)
            if (ptrace(PTRACE_SETOPTIONS, child_pid_, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) < 0) {
                 // PTRACE_O_TRACESYSGOOD helps distinguish syscall traps.
                 // If it fails, syscall command might be less reliable but shouldn't break others.
                 // perror("** ptrace(PTRACE_SETOPTIONS) failed"); // Optional: log error
            }
            
            program_loaded_ = true; 
            parse_elf_and_get_abs_entry(current_program_path_.c_str()); // Parse ELF after child is loaded and /proc exists

            if (is_pie_or_dyn_cached_ && base_address_ == 0 && entry_point_from_elf_ != 0 && text_segment_elf_va_ !=0) {
                // If base address is crucial for PIE and not found, it's an issue.
                // However, the dynamic linker handles much of this. We need to stop at the *target binary's* entry.
            }
            if (actual_loaded_entry_point_ == 0 && entry_point_from_elf_ == 0) { 
                std::cerr << "** Could not determine entry point for " << user_program_path_display_ << std::endl;
                kill_program(); return;
            }
            
            get_registers(); 
            // If the initial stop is not at the target binary's entry point (e.g., dynamic linker's entry point)
            // we need to set a temporary breakpoint at `actual_loaded_entry_point_` and continue.
            if (regs_.rip != actual_loaded_entry_point_ && actual_loaded_entry_point_ != 0) {
                long original_word_at_entry = peek_text(actual_loaded_entry_point_);
                if (errno != 0 && original_word_at_entry == -1) { 
                    std::cerr << "** Failed to read memory at calculated entry point 0x" << std::hex << actual_loaded_entry_point_ << std::dec << std::endl;
                    kill_program(); return;
                }
                long temp_bp_word = (original_word_at_entry & ~0xFFL) | 0xCC;
                poke_text(actual_loaded_entry_point_, temp_bp_word); 

                ptrace(PTRACE_CONT, child_pid_, nullptr, nullptr);
                if (waitpid(child_pid_, &status_, 0) < 0) { perror("** waitpid after temp BP failed"); kill_program(); return;}

                if (child_pid_ > 0) poke_text(actual_loaded_entry_point_, original_word_at_entry); // Restore
                
                if (WIFSTOPPED(status_) && WSTOPSIG(status_) == SIGTRAP) {
                    get_registers();
                    // After hitting the temp BP, RIP should be actual_loaded_entry_point_ + 1
                    if (regs_.rip == actual_loaded_entry_point_ + 1) { 
                        regs_.rip--; 
                        set_registers(); 
                    } else if (regs_.rip != actual_loaded_entry_point_){
                         // This is unexpected, RIP is not where we thought it would be.
                         // Forcibly set it if the spec requires stopping exactly at entry.
                         regs_.rip = actual_loaded_entry_point_; 
                         set_registers();
                    }
                } else { 
                     // Program didn't stop at the temp breakpoint as expected or terminated
                    std::cerr << "** Failed to stop at program entry point." << std::endl;
                    if (WIFEXITED(status_) || WIFSIGNALED(status_)) handle_wait_status(); else kill_program();
                    return;
                }
            }
            
            get_registers(); // Ensure regs_ are current
            
            std::cout << "** program '" << user_program_path_display_ << "' loaded. entry point 0x" << std::hex << actual_loaded_entry_point_ << "." << std::dec << std::endl;
            disassemble_instructions(regs_.rip, 5); 
            was_stopped_at_breakpoint_addr_ = 0; // Not stopped at a user BP initially
        }
    }
    
    void disassemble_instructions(unsigned long long start_address, int count) {
        if (!program_loaded_ || child_pid_ <= 0) return;

        const int MAX_INSTR_BYTES_PER_INS = 15; // Max x86-64 instruction length
        // Buffer needs to be large enough for 'count' instructions, each up to MAX_INSTR_BYTES_PER_INS
        // Plus a little extra to ensure we can read full words even if an instruction is short.
        unsigned char buffer[MAX_INSTR_BYTES_PER_INS * count + MAX_INSTR_BYTES_PER_INS]; 
        memset(buffer, 0, sizeof(buffer));
        size_t total_bytes_read = 0;
        
        unsigned long long current_instr_addr_for_check = start_address;

        for (int i = 0; i < count; ++i) { // Try to read enough bytes for `count` instructions
            // Ensure we don't read past buffer or too far if instructions are very long
            if (total_bytes_read >= sizeof(buffer) - MAX_INSTR_BYTES_PER_INS) break;

            if (i > 0 && !is_address_in_executable_region(current_instr_addr_for_check)) {
                // If subsequent instruction starts outside, stop.
                // The check for the *first* instruction is handled before cs_disasm.
                break;
            }
            
            unsigned long long word_aligned_peek_addr = (start_address + total_bytes_read) & ~(sizeof(long)-1);
            long word_data = peek_text(word_aligned_peek_addr);

            if (errno != 0 && word_data == -1) { 
                if (total_bytes_read == 0 && !is_address_in_executable_region(start_address)) {
                    // This case handled below before cs_disasm
                }
                break; // Error reading memory or end of readable region
            }

            size_t bytes_to_copy_from_word = sizeof(long);
            size_t offset_in_word = (start_address + total_bytes_read) % sizeof(long);

            for (size_t k = offset_in_word; k < sizeof(long); ++k) {
                if (total_bytes_read >= sizeof(buffer)) break;
                
                unsigned long long current_byte_actual_addr = word_aligned_peek_addr + k;
                unsigned char byte_val = (reinterpret_cast<unsigned char*>(&word_data))[k];
                
                auto bp_it = breakpoints_map_.find(current_byte_actual_addr); 
                // If this byte is the start of an instruction that has a breakpoint, use original byte.
                // This substitution should ideally happen per-instruction byte, not just the first byte of a word.
                // The current logic applies it if current_byte_actual_addr *is* a breakpoint address.
                // This is okay for single-byte 0xCC.
                if (bp_it != breakpoints_map_.end() && (bp_it->second & 0xFF) != 0xCC) { // If it's a BP location
                    buffer[total_bytes_read++] = (unsigned char)(bp_it->second & 0xFF); 
                } else {
                    buffer[total_bytes_read++] = byte_val;
                }
            }
             // This logic is a bit complex for filling the buffer. Simpler: read N words, then cs_disasm.
             // The loop condition for 'i' and 'total_bytes_read' should aim to get enough data.
             // A simpler approach: read (MAX_INSTR_BYTES_PER_INS * count) bytes if possible.
             if (i == 0) current_instr_addr_for_check += 1; // placeholder for advancing check, cs_disasm gives true length
        }
        // Re-simplifying buffer read:
        total_bytes_read = 0;
        current_instr_addr_for_check = start_address; // Reset for cs_disasm context
        if (!is_address_in_executable_region(start_address) && start_address !=0) {
             std::cout << "** the address is out of the range of the executable region." << std::endl;
             return;
        }

        for (unsigned long long current_peek_addr = start_address; 
             total_bytes_read < sizeof(buffer) - sizeof(long) && total_bytes_read < (size_t)(MAX_INSTR_BYTES_PER_INS * (count + 2)); // Read a bit more
             current_peek_addr += sizeof(long)) {
            
            if (!is_address_in_executable_region(current_peek_addr) && current_peek_addr > start_address) { // Stop if we leave region
                break;
            }
            long word_data = peek_text(current_peek_addr);
            if (errno != 0 && word_data == -1) { break; }

            for (size_t k=0; k < sizeof(long); ++k) { 
                if (total_bytes_read >= sizeof(buffer)) break; 
                unsigned long long byte_addr = current_peek_addr + k;
                unsigned char byte_val = (reinterpret_cast<unsigned char*>(&word_data))[k];
                
                auto bp_it = breakpoints_map_.find(byte_addr); 
                if (bp_it != breakpoints_map_.end()) { 
                    buffer[total_bytes_read++] = (unsigned char)(bp_it->second & 0xFF); 
                } else {
                    buffer[total_bytes_read++] = byte_val;
                }
            }
        }


        if (total_bytes_read == 0) { // Failed to read any byte or initial address out of region
            if (!is_address_in_executable_region(start_address) && start_address !=0) {
                 // Message already printed if start_address was bad. Or print here if it became bad.
            } else {
                 // Could not read, even if address was initially in region.
                 std::cout << "** failed to read instructions at 0x" << std::hex << start_address << std::dec << "." << std::endl;
            }
            return;
        }


        cs_insn *insn_array;
        size_t num_insns_disassembled = cs_disasm(capstone_handle_, buffer, total_bytes_read, start_address, 0, &insn_array); 

        std::cout << std::left; 

        size_t displayed_count = 0;
        if (num_insns_disassembled > 0) {
            for (size_t i = 0; i < num_insns_disassembled && displayed_count < static_cast<size_t>(count); ++i) {
                if (!is_address_in_executable_region(insn_array[i].address) && insn_array[i].address != 0) {
                    // This instruction is out of bounds. If it's the first one, the message was already printed.
                    // If not the first, then previous ones were okay.
                    if (displayed_count == 0 && i == 0) {
                        // This case should have been caught before cs_disasm for start_address
                    } else if (displayed_count > 0) { // We printed some, now this one is out.
                         std::cout << "** the address is out of the range of the executable region." << std::endl;
                    }
                    break; 
                }
                std::cout << "      0x" << std::hex << insn_array[i].address << ": " << std::dec; 
                std::string bytes_str;
                for (size_t j = 0; j < insn_array[i].size; ++j) {
                    std::stringstream temp_ss;
                    temp_ss << std::setw(2) << std::setfill('0') << std::hex << (int)insn_array[i].bytes[j];
                    bytes_str += (j == 0 ? "" : " ") + temp_ss.str();
                }
                std::cout << std::left << std::setw(30) << bytes_str; 
                std::cout << std::setw(10) << insn_array[i].mnemonic; 
                std::cout << insn_array[i].op_str << std::endl;
                displayed_count++;
                current_instr_addr_for_check = insn_array[i].address + insn_array[i].size; // For next iteration check
            }
            
            cs_free(insn_array, num_insns_disassembled);
            
            if (displayed_count < static_cast<size_t>(count)) {
                 // If we displayed some, and the *next* instruction would be out of bounds:
                if (displayed_count > 0 && !is_address_in_executable_region(current_instr_addr_for_check) && current_instr_addr_for_check != 0) {
                    std::cout << "** the address is out of the range of the executable region." << std::endl;
                } else if (displayed_count == 0 && num_insns_disassembled == 0 && total_bytes_read > 0) { 
                    // Read bytes but couldn't disassemble anything, and start_address was in region.
                    // This could mean invalid opcodes. Capstone might return 0.
                    // The spec implies this message if *address* is OOR.
                }
            }
        } else { // cs_disasm returned 0 instructions
            // This could mean start_address was already out of region (handled), or invalid opcodes.
            // If start_address was valid but no instructions could be disassembled:
            if (is_address_in_executable_region(start_address)) {
                 // Maybe print nothing or a different error? Spec is for address OOR.
                 // If total_bytes_read was also 0, it's already handled.
            } else if (start_address != 0) { // Already handled by check at the top of function
                 // std::cout << "** the address is out of the range of the executable region." << std::endl;
            }
        }
        std::cout << std::right << std::flush; 
    }

    void handle_wait_status() { 
        if (child_pid_ <= 0 && !(WIFEXITED(status_) || WIFSIGNALED(status_))) { return; }

        if (WIFEXITED(status_)) {
            std::cout << "** the target program terminated." << std::endl;
            program_loaded_ = false; child_pid_ = -1; was_stopped_at_breakpoint_addr_ = 0; 
            // Full reset of states for next load
            breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); text_segment_elf_va_ = 0; text_segment_size_ = 0;
            executable_regions_.clear(); next_breakpoint_id_ = 0; load_offset_ = 0;
            actual_loaded_entry_point_ = 0; base_address_ = 0; entry_point_from_elf_ = 0;
            text_segment_start_ = 0;
            return;
        } else if (WIFSIGNALED(status_)) {
            std::cout << "** the target program terminated by signal " << strsignal(WTERMSIG(status_)) << "." << std::endl;
            program_loaded_ = false; child_pid_ = -1; was_stopped_at_breakpoint_addr_ = 0; 
            // Full reset
            breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); text_segment_elf_va_ = 0; text_segment_size_ = 0;
            executable_regions_.clear(); next_breakpoint_id_ = 0; load_offset_ = 0;
            actual_loaded_entry_point_ = 0; base_address_ = 0; entry_point_from_elf_ = 0;
            text_segment_start_ = 0;
            return;
        }
        else if (WIFSTOPPED(status_)) {
            int sig = WSTOPSIG(status_);
            get_registers(); 
            if (child_pid_ <= 0) { // Child died during get_registers or was already dead
                if (program_loaded_) { /* This should not happen if child_pid_ <= 0 */ }
                program_loaded_ = false; // Ensure state is consistent
                was_stopped_at_breakpoint_addr_ = 0; 
                return;
            }

            bool event_handled_and_disassembled = false;
            unsigned long long rip_as_reported_by_kernel = regs_.rip; 

            // was_stopped_at_breakpoint_addr_ refers to the breakpoint we *were* on at the *previous* stop,
            // whose original byte was restored. We reset it now for the *current* stop.
            // It will be set again if this current stop is a breakpoint that we handle by restoring its byte.
            // unsigned long long previous_bp_address_we_were_on = was_stopped_at_breakpoint_addr_; // For complex logic if needed
            was_stopped_at_breakpoint_addr_ = 0; 

            if (sig == SIGTRAP) {
                unsigned long long bp_addr_if_int3 = rip_as_reported_by_kernel - 1; 
                auto bp_iter_if_int3 = breakpoints_map_.find(bp_addr_if_int3);

                auto bp_iter_if_direct_land = breakpoints_map_.find(rip_as_reported_by_kernel);

                if (bp_iter_if_int3 != breakpoints_map_.end()) { // Common case: PTRACE_CONT hits an INT3
                    regs_.rip = bp_addr_if_int3; 
                    set_registers();              

                    std::cout << "** hit a breakpoint at 0x" << std::hex << regs_.rip << "." << std::dec << std::endl;

                    poke_text(regs_.rip, bp_iter_if_int3->second); 
                    was_stopped_at_breakpoint_addr_ = regs_.rip;   
                    disassemble_instructions(regs_.rip, 5);
                    event_handled_and_disassembled = true;
                }
                else if (bp_iter_if_direct_land != breakpoints_map_.end()) { // PTRACE_SINGLESTEP lands on a BP addr
                    // regs_.rip is already the BP address
                    std::cout << "** hit a breakpoint at 0x" << std::hex << regs_.rip << "." << std::dec << std::endl;
                    poke_text(regs_.rip, bp_iter_if_direct_land->second); 
                    was_stopped_at_breakpoint_addr_ = regs_.rip;       
                    disassemble_instructions(regs_.rip, 5);
                    event_handled_and_disassembled = true;
                }
                // Syscall trap handling (PTRACE_O_TRACESYSGOOD helps distinguish via WSTOPSIG(status) & 0x80)
                // Or, if using PTRACE_SYSCALL, current_command_ helps.
                else if (current_command_ == "syscall" && ( (WSTOPSIG(status_) & 0x80) || sig == SIGTRAP ) ) { 
                    // The (sig == SIGTRAP) is a fallback if TRACESYSGOOD wasn't set or effective.
                    // We must ensure this is not a breakpoint.
                    unsigned long long syscall_instr_addr = rip_as_reported_by_kernel - 2; // syscall (0f 05) is 2 bytes
                    
                    if (breakpoints_map_.find(syscall_instr_addr) == breakpoints_map_.end()) { // Not a BP on the syscall itself
                        long syscall_num_val = regs_.orig_rax; 
                        long ret_val_val = regs_.rax;      

                        if (in_syscall_entry_) { 
                            std::cout << "** enter a syscall(" << std::dec << syscall_num_val << ") at 0x" << std::hex << syscall_instr_addr << "." << std::dec << std::endl;
                            in_syscall_entry_ = false; 
                        } else {
                            std::cout << "** leave a syscall(" << std::dec << syscall_num_val << ") = " << std::dec << ret_val_val << " at 0x" << std::hex << syscall_instr_addr << "." << std::dec << std::endl;
                        }
                        disassemble_instructions(syscall_instr_addr, 5);
                        event_handled_and_disassembled = true;
                    }
                }
            } else if (sig == SIGWINCH) {
                if (program_loaded_ && child_pid_ > 0) {
                    ptrace(PTRACE_CONT, child_pid_, nullptr, (void*)((long)sig)); // Pass signal to child
                    if (waitpid(child_pid_, &status_, 0) < 0 ) { // Wait for child to stop or terminate
                         if(program_loaded_) { child_pid_ = -1; program_loaded_ = false;} // Update state if wait failed
                    }
                    // After PTRACE_CONT with signal, child will either terminate or stop again.
                    // Call handle_wait_status to process this new state.
                    handle_wait_status(); // Process the new state
                    return; // SIGWINCH and its immediate effect are handled.
                }
            } else { // Other signals
                if (program_loaded_ && child_pid_ > 0) {
                    std::cout << "** Child stopped by signal " << strsignal(sig) << " (SIG=" << sig << ")" << std::endl;
                }
            }

            if (!event_handled_and_disassembled && program_loaded_ && child_pid_ > 0) {
                // If not a recognized breakpoint or handled syscall trap, disassemble from current (kernel reported) RIP
                disassemble_instructions(rip_as_reported_by_kernel, 5);
            }
        }
    }


    void step_instruction() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        in_syscall_entry_ = false; 
        get_registers();
        unsigned long long rip_to_step_from = regs_.rip;

        // If we were stopped at a breakpoint, its original instruction is currently restored.
        // was_stopped_at_breakpoint_addr_ would be rip_to_step_from if handle_wait_status processed it.
        bool stepping_from_restored_bp = (was_stopped_at_breakpoint_addr_ == rip_to_step_from);
        // Note: was_stopped_at_breakpoint_addr_ is reset at the start of handle_wait_status.
        // It's set again if handle_wait_status identifies the *current* stop as a BP and restores it.
        // For 'si', was_stopped_at_breakpoint_addr_ should be the address of the BP if we are on one.

        if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) { 
             if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
             return; 
        }
        if (waitpid(child_pid_, &status_, 0) < 0) { 
            if (program_loaded_) { child_pid_ = -1; program_loaded_ = false; }
            return;
        }

        // After single step, if we stepped off a breakpoint, re-enable that breakpoint.
        if (stepping_from_restored_bp) { 
            auto bp_it = breakpoints_map_.find(rip_to_step_from);
            if (bp_it != breakpoints_map_.end()) { 
                if (child_pid_ > 0 && program_loaded_) { // Check if child still valid
                    // Re-insert 0xCC using the original data stored in breakpoint_map
                    long rearm_word = (bp_it->second & ~0xFFL) | 0xCC;
                    poke_text(rip_to_step_from, rearm_word);
                }
            }
        }
        
        handle_wait_status(); 
    }

    void continue_execution() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        in_syscall_entry_ = false;
        get_registers();
        unsigned long long rip_at_cont_start = regs_.rip;

        // If we are currently stopped AT a breakpoint (its original byte is restored, 0xCC is not there)
        // we must first execute this single instruction, then re-insert 0xCC, then PTRACE_CONT.
        if (was_stopped_at_breakpoint_addr_ == rip_at_cont_start) {
            if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) { 
                if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
                return; 
            }
            int temp_status_after_step; // Use a temporary status for this intermediate step
            if (waitpid(child_pid_, &temp_status_after_step, 0) < 0) {
                if (program_loaded_) {child_pid_ = -1; program_loaded_ = false;} 
                return;
            }

            // Re-arm the breakpoint we just stepped over
            if (child_pid_ > 0 && program_loaded_) { // Check if child still valid
                auto bp_it = breakpoints_map_.find(rip_at_cont_start);
                if (bp_it != breakpoints_map_.end()) { 
                    long rearm_word = (bp_it->second & ~0xFFL) | 0xCC;
                    poke_text(rip_at_cont_start, rearm_word);
                }
            } else { // Child died or problem during step
                status_ = temp_status_after_step; 
                handle_wait_status(); // Process this termination/unexpected stop
                return; 
            }

            // If program terminated or had another critical stop during this single step
            if (WIFEXITED(temp_status_after_step) || WIFSIGNALED(temp_status_after_step)) {
                status_ = temp_status_after_step; 
                handle_wait_status(); 
                return; 
            }
            // If it stopped for another reason (e.g. another breakpoint hit by the single step)
            // This is complex: the spec for `cont` is usually about continuing until *next* BP or termination.
            // For now, we assume the single step completes one instruction.
            // The main status_ should reflect the state *after* this step if we are not PTRACE_CONTing further immediately.
            // However, we are about to PTRACE_CONT.
            status_ = temp_status_after_step; // Update main status for PTRACE_CONT's perspective
        }
        
        // was_stopped_at_breakpoint_addr_ is reset by handle_wait_status.
        // If we just stepped off a BP, it's now 0.
        // If we were not on a BP, it was already 0.

        if (child_pid_ > 0 && program_loaded_) { // Ensure child is still valid before PTRACE_CONT
            if (ptrace(PTRACE_CONT, child_pid_, nullptr, nullptr) < 0) { 
                if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
                return; 
            }
            if (waitpid(child_pid_, &status_, 0) < 0) {
                if (program_loaded_) {child_pid_ = -1; program_loaded_ = false;}
                return;
            }
            handle_wait_status(); // Handle the result of PTRACE_CONT
        }
    }

    void handle_syscall_command() {
        if (!program_loaded_ || child_pid_ <= 0) return;
        get_registers();
        unsigned long long rip_at_cmd_start = regs_.rip;
        
        // Similar to 'cont', if we are on a restored breakpoint, step over it first.
        if (was_stopped_at_breakpoint_addr_ == rip_at_cmd_start) {
            if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) { /* error handling */ return; }
            int temp_status;
            if (waitpid(child_pid_, &temp_status, 0) < 0) { /* error handling */ return;}
            
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
            // If the single step hit another breakpoint or a syscall entry/exit, handle_wait_status should sort it out.
            // For now, we update status_ and proceed to PTRACE_SYSCALL.
            status_ = temp_status; // This status is from the single step.
            
            // If this single step itself results in a stop that should be reported (e.g. new breakpoint)
            // then handle_wait_status should be called here.
            // But the goal of 'syscall' command is to stop at syscall, not intermediate BPs *unless specified*.
            // Spec: "break at every system call instruction unless it hits a breakpoint."
            // If this single step hits a breakpoint:
            if (WIFSTOPPED(status_) && WSTOPSIG(status_) == SIGTRAP) {
                 get_registers(); // Update regs_ for handle_wait_status
                 unsigned long long current_rip_after_step = regs_.rip;
                 unsigned long long bp_addr_if_int3_after_step = current_rip_after_step - 1;
                 if (breakpoints_map_.count(bp_addr_if_int3_after_step) || breakpoints_map_.count(current_rip_after_step)) {
                     handle_wait_status(); // This step hit a breakpoint, report it.
                     return; // Don't proceed to PTRACE_SYSCALL for this command.
                 }
            }
        }
        
        // was_stopped_at_breakpoint_addr_ is reset by handle_wait_status or should be 0 here.
        
        if (child_pid_ > 0 && program_loaded_) {
            // Determine if we are expecting syscall entry or exit.
            // If handle_wait_status just processed a syscall entry, in_syscall_entry_ is false.
            // If it just processed a syscall exit, in_syscall_entry_ is still false (it means next will be entry).
            // So, before PTRACE_SYSCALL, if we are not already in a syscall sequence (e.g. just after "syscall" command)
            // we are expecting an entry.
            // The in_syscall_entry_ flag in handle_wait_status is toggled *after* printing.
            // So if it's false, it means we just left a syscall OR we are about to enter the first one.
            if (!in_syscall_entry_) { // If previous was exit or this is the first PTRACE_SYSCALL for this command
                in_syscall_entry_ = true; // We are now aiming for a syscall entry.
            }
            // If in_syscall_entry_ was true (meaning we were at entry, now aiming for exit), it remains true,
            // and handle_wait_status will see it as true, print "enter", then set it to false. This seems backward.

            // Simpler: `in_syscall_entry_` should be true if the *next* stop we want is an entry.
            // And false if the *next* stop we want is an exit.
            // Let handle_wait_status manage toggling it based on what it prints.
            // Before the *first* PTRACE_SYSCALL of a "syscall" command, set it to true.
            // The `handle_syscall_command` will call PTRACE_SYSCALL.
            // `handle_wait_status` will see `in_syscall_entry_` as true, print "enter", set to false.
            // Next `PTRACE_SYSCALL` from `handle_syscall_command`, `handle_wait_status` sees false, prints "leave", (keeps it false for next entry).
            // This logic seems fine.

            if (ptrace(PTRACE_SYSCALL, child_pid_, nullptr, nullptr) < 0) {
                if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; }
                // in_syscall_entry_ might need reset if ptrace fails early
                return;
            }
            if (waitpid(child_pid_, &status_, 0) < 0) {
                if(program_loaded_) {child_pid_ = -1; program_loaded_ = false;} 
                return;
            }
            // If program exited/signaled during PTRACE_SYSCALL, in_syscall_entry_ might be stale for next command.
            // handle_wait_status will reset program_loaded_ which implicitly resets context for next load.
            handle_wait_status();
        }
    }


    void print_registers() {
        if (!program_loaded_ || child_pid_ <=0) { 
            // If called before load, spec says "please load a program first"
            // This is handled by the main loop's program_loaded_ check.
            // If called when program_loaded_ is true but child_pid_ is bad, means something went wrong.
            return; 
        }
        if (ptrace(PTRACE_GETREGS, child_pid_, nullptr, &regs_) < 0) {
            if (errno == ESRCH) { program_loaded_ = false; child_pid_ = -1; } // Child died
            return;
        }

        std::ios_base::fmtflags original_flags = std::cout.flags(); 
        std::cout << std::hex << std::setfill('0');
        std::cout << "$rax 0x" << std::setw(16) << regs_.rax << "   $rbx 0x" << std::setw(16) << regs_.rbx << "   $rcx 0x" << std::setw(16) << regs_.rcx << std::endl;
        std::cout << "$rdx 0x" << std::setw(16) << regs_.rdx << "   $rsi 0x" << std::setw(16) << regs_.rsi << "   $rdi 0x" << std::setw(16) << regs_.rdi << std::endl;
        std::cout << "$rbp 0x" << std::setw(16) << regs_.rbp << "   $rsp 0x" << std::setw(16) << regs_.rsp << "   $r8  0x" << std::setw(16) << regs_.r8  << std::endl;
        std::cout << "$r9  0x" << std::setw(16) << regs_.r9  << "   $r10 0x" << std::setw(16) << regs_.r10 << "   $r11 0x" << std::setw(16) << regs_.r11 << std::endl;
        std::cout << "$r12 0x" << std::setw(16) << regs_.r12 << "   $r13 0x" << std::setw(16) << regs_.r13 << "   $r14 0x" << std::setw(16) << regs_.r14 << std::endl;
        std::cout << "$r15 0x" << std::setw(16) << regs_.r15 << "   $rip 0x" << std::setw(16) << regs_.rip << "   $eflags 0x" << std::setw(16) << regs_.eflags << std::endl;
        std::cout.flags(original_flags); 
    }

    void set_breakpoint_common(unsigned long long addr, bool is_rva) {
        if (!program_loaded_ || child_pid_ <= 0) { return; }
        
        bool is_valid_addr_for_bp = false;
        // Check specific text segment if known and matches
        if (text_segment_start_ != 0 && text_segment_size_ != 0) {
            if (addr >= text_segment_start_ && addr < text_segment_start_ + text_segment_size_) {
                is_valid_addr_for_bp = true;
            }
        }
        // If not in primary text, check other executable regions from maps (more general)
        if (!is_valid_addr_for_bp) { 
            for(const auto& region : executable_regions_){
                if(addr >= region.first && addr < region.second){
                    is_valid_addr_for_bp = true;
                    break;
                }
            }
        }

        if (!is_valid_addr_for_bp) { 
            std::cout << "** the target address is not valid." << std::endl; return;
        }

        if (breakpoints_map_.count(addr)) { 
            // Breakpoint already exists, spec doesn't say what to do. Silently ignore or re-confirm?
            // GDB usually just confirms. For simplicity, ignore if already set.
            return; 
        }
        
        long original_word = peek_text(addr);
        // peek_text returns -1 on error and sets errno.
        if (errno != 0 && original_word == -1) { // Check errno because -1 can be valid data.
            std::cout << "** the target address is not valid." << std::endl; return;
        }
        
        breakpoints_map_[addr] = original_word; // Store the original word
        breakpoint_id_to_addr_[next_breakpoint_id_] = addr;
        
        long new_word_with_int3 = (original_word & ~0xFFL) | 0xCC; // Place 0xCC in the LSB
        poke_text(addr, new_word_with_int3);
        
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
        
        // base_address_ is calculated in parse_elf_and_get_abs_entry
        // For non-PIE, base_address_ might be 0 if ELF loads at 0, or the fixed load like 0x400000.
        // For PIE, it's the ASLR base.
        if (base_address_ == 0 && is_pie_or_dyn_cached_ && entry_point_from_elf_ != 0 && text_segment_elf_va_ != 0) { 
            // If it's PIE and we couldn't determine a base_address from maps, RVA is problematic.
            // However, if entry_point is already absolute due to linker, base_address might be 0.
            // This condition needs to be robust.
            // The current base_address calculation from maps (first segment with offset 0) should be okay.
        }
        unsigned long long addr = base_address_ + offset; 
        set_breakpoint_common(addr, true);
    }

    void info_breakpoints() {
        if (!program_loaded_) { return; } // Should be caught by main loop
        std::vector<std::pair<int, unsigned long long>> sorted_bps_for_display;
        for(const auto& pair_id_addr : breakpoint_id_to_addr_){
            // Only list active breakpoints still in breakpoints_map_
            if(breakpoints_map_.count(pair_id_addr.second)){ 
                sorted_bps_for_display.push_back({pair_id_addr.first, pair_id_addr.second});
            }
        }
        // Spec: "If a breakpoint is deleted, the index of the other breakpoints should remain the same."
        // "if you add a new breakpoint, continue the indexing instead of filling the deleted index."
        // This is handled by using next_breakpoint_id_ and not reusing IDs.
        // Sorting by ID for display is good.
        std::sort(sorted_bps_for_display.begin(), sorted_bps_for_display.end()); 

        if (sorted_bps_for_display.empty()) { std::cout << "** no breakpoints." << std::endl; return; }

        std::cout << "Num      Address" << std::endl; // Adjusted spacing for alignment
        for (const auto& pair_id_addr : sorted_bps_for_display) {
            std::cout << std::left << std::setw(8) << pair_id_addr.first // setw for Num
                      << "0x" << std::hex << pair_id_addr.second << std::dec << std::endl;
        }
    }

    void delete_breakpoint(int id) {
        if (!program_loaded_ || child_pid_ <= 0) { return; }
        auto id_it = breakpoint_id_to_addr_.find(id);
        if (id_it == breakpoint_id_to_addr_.end()) {
            std::cout << "** breakpoint " << id << " does not exist." << std::endl; return;
        }

        unsigned long long addr = id_it->second;
        auto bp_it = breakpoints_map_.find(addr);
        if (bp_it == breakpoints_map_.end()) { 
            // ID exists but breakpoint data is gone (inconsistent state, should not happen)
            std::cout << "** breakpoint " << id << " does not exist (internal error)." << std::endl;
            breakpoint_id_to_addr_.erase(id_it); // Clean up ID map too
            return;
        }

        // Restore original instruction byte
        poke_text(addr, bp_it->second); // bp_it->second is the original word
        
        breakpoints_map_.erase(bp_it); 
        breakpoint_id_to_addr_.erase(id_it); // Remove from ID mapping
        std::cout << "** delete breakpoint " << id << "." << std::endl;
    }

    void patch_memory(const std::string& addr_str, const std::string& hex_values_str) {
        if (!program_loaded_ || child_pid_ <= 0) { return; }
        unsigned long long start_addr;
        try { start_addr = hex_to_ullong(addr_str); } 
        catch (const std::exception& e) { std::cout << "** the target address is not valid." << std::endl; return; }

        if (hex_values_str.length() % 2 != 0 || hex_values_str.length() > 2048 || hex_values_str.empty()) {
            // Spec doesn't require handling empty hex string error explicitly, but implies valid hex string
            std::cout << "** the target address is not valid (invalid hex string format/length)." << std::endl; return;
        }

        std::vector<unsigned char> bytes_to_patch;
        for (size_t i = 0; i < hex_values_str.length(); i += 2) {
            std::string byte_str = hex_values_str.substr(i, 2);
            try { 
                unsigned long byte_val_long = std::stoul(byte_str, nullptr, 16);
                if (byte_val_long > 0xFF) throw std::out_of_range("byte value out of range");
                bytes_to_patch.push_back(static_cast<unsigned char>(byte_val_long)); 
            } 
            catch (const std::exception& e) { std::cout << "** the target address is not valid (invalid hex char in string)." << std::endl; return; }
        }
        if (bytes_to_patch.empty() && !hex_values_str.empty()){ 
             // This case should be caught by stoul errors if hex_values_str is not empty but invalid
             std::cout << "** the target address is not valid (hex string parsing failed)." << std::endl; return;
        }
        
        // Check validity of the entire range to be patched
        for (size_t i = 0; i < bytes_to_patch.size(); ++i) {
            // For patch, "valid address" might mean writable, not just executable.
            // The spec doesn't strictly say "executable region" for patch.
            // A simple check: can we PEEK/POKE it? ptrace will fail if not.
            // For now, let's use is_address_in_executable_region as a proxy, though this might be too strict.
            // The spec note implies patching executable regions (patched instructions).
            if (!is_address_in_executable_region(start_addr + i) && text_segment_start_ != 0) { // text_segment_start_ check to avoid false positive if regions not populated fully
                // More robust: try to peek the first and last byte's word. If fails, then invalid.
                // For simplicity with current structure, rely on is_address_in_executable_region or successful pokes.
            }
        }
         // The actual poke will fail if address is truly invalid.
         // The spec asks to check "address + sizeof([hex string]) is not a valid address".

        unsigned long long end_addr_check = start_addr + bytes_to_patch.size() -1;
        if (!bytes_to_patch.empty()) { // only check if there are bytes to patch
            errno = 0;
            peek_text(start_addr);
            if (errno != 0) { std::cout << "** the target address is not valid." << std::endl; return; }
            if (bytes_to_patch.size() > 1) {
                errno = 0;
                peek_text(end_addr_check); // Check last byte's word
                 if (errno != 0) { std::cout << "** the target address is not valid." << std::endl; return; }
            }
        }


        for (size_t i = 0; i < bytes_to_patch.size(); ++i) {
            unsigned long long current_byte_addr = start_addr + i;
            unsigned char byte_to_write = bytes_to_patch[i];
            
            unsigned long long word_aligned_addr = current_byte_addr & ~(sizeof(long)-1); // Align to word boundary for PEEK/POKE
            int byte_offset_in_word = current_byte_addr % sizeof(long);
            
            long current_word_val = peek_text(word_aligned_addr);
            if (errno != 0 && current_word_val == -1) { 
                std::cout << "** the target address is not valid (read failed during patch)." << std::endl; 
                // May need to revert previous patches if partial failure desired, but spec doesn't require.
                return;
            }

            long original_word_for_bp_map = current_word_val; // This is the word *before* our patch.

            // Modify the byte in the word
            (reinterpret_cast<unsigned char*>(&current_word_val))[byte_offset_in_word] = byte_to_write;
            
            // If this address is a breakpoint, update its stored original_data to reflect the patch
            auto bp_it = breakpoints_map_.find(current_byte_addr);
            if (bp_it != breakpoints_map_.end()) {
                // The breakpoint was at current_byte_addr. Its original_data (a word) needs to be updated
                // as if this patch was the "original" instruction byte.
                (reinterpret_cast<unsigned char*>(&(bp_it->second)))[byte_offset_in_word] = byte_to_write;
                // The 0xCC is still in memory at current_byte_addr. Our poke_text below will overwrite it.
                // Then, when the BP is hit, the (now patched) original_data will be restored.
                // This seems to fulfill "breakpoint should still exist, but the original instruction should be patched."
            }
            
            poke_text(word_aligned_addr, current_word_val); // Write the modified word
            if (errno == ESRCH) { // child died during poke
                 std::cout << "** the target address is not valid (write failed during patch, child died)." << std::endl; return;
            }
        }
        std::cout << "** patch memory at 0x" << std::hex << start_addr << "." << std::dec << std::endl;
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