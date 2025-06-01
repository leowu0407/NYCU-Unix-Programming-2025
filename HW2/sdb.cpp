#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <map>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <limits.h>
#include <cerrno>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <elf.h>
#include <capstone/capstone.h>
#include <fcntl.h>


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

class Debugger {
private:
    pid_t child_pid_;
    bool program_loaded_;
    std::string current_program_path_;
    std::string user_program_path_display_;
    std::string proc_exe_path_cached_;
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

    std::map<unsigned long long, unsigned char> breakpoints_map_;
    std::map<int, unsigned long long> breakpoint_id_to_addr_;
    int next_breakpoint_id_;

    csh capstone_handle_;
    std::vector<std::pair<unsigned long long, unsigned long long>> executable_regions_;

    bool in_syscall_entry_;
    std::string current_command_;
    bool is_pie_or_dyn_cached_;

    void refresh_executable_regions();
    void handle_program_termination();


public:
    Debugger();
    ~Debugger();
    void run(const std::string& initial_program_path_arg = "");

private:
    void kill_program();
    long peek_text(unsigned long long addr);
    void poke_text(unsigned long long addr, long data);
    void get_registers_from_child();
    void set_registers_in_child();
    bool is_address_in_executable_region(unsigned long long addr);
    void parse_elf_and_get_abs_entry(const char* program_file_path);
    void load_program_internal(char** argv_for_exec);
    void disassemble_instructions(unsigned long long start_address, int count);
    void handle_wait_status();
    void step_instruction();
    void continue_execution();
    void handle_syscall_command();
    void print_registers();
    void set_breakpoint_common(unsigned long long addr, bool is_rva_command);
    void set_breakpoint(const std::string& addr_str);
    void set_breakpoint_rva(const std::string& offset_str);
    void info_breakpoints();
    void delete_breakpoint(int id);
    void patch_memory(const std::string& addr_str, const std::string& hex_values_str);

    void restore_original_byte_at_bp(unsigned long long bp_addr, unsigned char original_byte);
    void rearm_breakpoint(unsigned long long bp_addr);
    void process_breakpoint_hit(unsigned long long bp_addr);

};


Debugger::Debugger() :
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
    in_syscall_entry_(true),
    is_pie_or_dyn_cached_(false)
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle_) != CS_ERR_OK) {
        std::cerr << "** Capstone initialization failed." << std::endl;
        exit(EXIT_FAILURE);
    }
}

Debugger::~Debugger() {
    if (capstone_handle_ != 0) {
        cs_close(&capstone_handle_);
    }
    if (child_pid_ > 0) {
        kill_program();
    }
}

void Debugger::run(const std::string& initial_program_path_arg) {
    // Input/Output Not Buffered
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stdin, nullptr, _IONBF, 0);

    if (!initial_program_path_arg.empty()) {
        user_program_path_display_ = initial_program_path_arg;
        char* prog_name_c_str = strdup(user_program_path_display_.c_str());
        char* argv_for_load[] = {prog_name_c_str, nullptr};
        load_program_internal(argv_for_load);
        free(prog_name_c_str);
    }

    std::string line;
    while (true) {
        std::cout << "(sdb) " << std::flush;
        if (!std::getline(std::cin, line)) {
            if (child_pid_ > 0) kill_program();
            break;
        }

        std::vector<std::string> args = split_string(line, ' ');
        if (args.empty() || args[0].empty()) {
            continue;
        }

        current_command_ = args[0];

        if (current_command_ == "load") {
            if (child_pid_ > 0) kill_program();

            if (args.size() < 2) {
                std::cerr << "** Usage: load [path to program]" << std::endl;
            } 
            else {
                user_program_path_display_ = args[1];
                char* loaded_prog_name_c_str = strdup(args[1].c_str());
                if (!loaded_prog_name_c_str) { 
                    std::cerr << "** Memory allocation failed for loaded program name." << std::endl; 
                    continue;
                }
                char* argv_for_exec[] = {loaded_prog_name_c_str, nullptr};
                load_program_internal(argv_for_exec);
                free(loaded_prog_name_c_str);
            }
        }
        else if (current_command_ == "exit" || current_command_ == "quit" || current_command_ == "q") {
            kill_program();
            break;
        }
        else if (!program_loaded_) {
            if (current_command_ == "si" || current_command_ == "cont" || current_command_ == "info" ||
                current_command_ == "break" || current_command_ == "breakrva" || current_command_ == "delete" ||
                current_command_ == "patch" || current_command_ == "syscall") {
                std::cout << "** please load a program first." << std::endl;
            } 
            else if (!current_command_.empty()) {
                std::cout << "** Unknown command: " << current_command_ << std::endl;
            }
        }
        else {
            if (child_pid_ == -1 && (WIFEXITED(status_) || WIFSIGNALED(status_))) {
                 program_loaded_ = false;
                 continue;
            }

            if (current_command_ == "si") {
                step_instruction();
            } 
            else if (current_command_ == "cont") {
                continue_execution();
            } 
            else if (current_command_ == "info") {
                if (args.size() > 1 && args[1] == "reg") {
                    print_registers();
                } 
                else if (args.size() > 1 && args[1] == "break") {
                    info_breakpoints();
                } 
                else {
                    std::cout << "** Usage: info reg | info break" << std::endl;
                }
            } 
            else if (current_command_ == "break") {
                if (args.size() < 2) {
                    std::cout << "** Usage: break [hex address]" << std::endl;
                } 
                else {
                    set_breakpoint(args[1]);
                }
            } 
            else if (current_command_ == "breakrva") {
                if (args.size() < 2) {
                    std::cout << "** Usage: breakrva [hex offset]" << std::endl;
                } 
                else {
                    set_breakpoint_rva(args[1]);
                }
            } 
            else if (current_command_ == "delete") {
                if (args.size() < 2) {
                    std::cout << "** Usage: delete [id]" << std::endl;
                } 
                else {
                    try {
                        delete_breakpoint(std::stoi(args[1]));
                    } 
                    catch (const std::exception& e) {
                        std::cout << "** Invalid breakpoint id format." << std::endl;
                    }
                }
            } 
            else if (current_command_ == "patch") {
                if (args.size() < 3) {
                    std::cout << "** Usage: patch [hex address] [hex string]" << std::endl;
                } 
                else {
                    patch_memory(args[1], args[2]);
                }
            } 
            else if (current_command_ == "syscall") {
                handle_syscall_command();
            }
            else if (!current_command_.empty()) {
                std::cout << "** Unknown command: " << current_command_ << std::endl;
            }
        }
    }
}

void Debugger::kill_program() {
    if (child_pid_ > 0) {
        if (program_loaded_) {
            for (auto const& [addr, original_byte_val] : breakpoints_map_) {
                if (child_pid_ <= 0) {
                    break;
                }
                unsigned long long aligned_addr = addr & ~(sizeof(long)-1);
                int byte_offset = addr % sizeof(long);
                errno = 0;
                long current_word_in_mem = peek_text(aligned_addr);

                if (errno == 0 && current_word_in_mem != -1L) {
                    if (((unsigned char*)&current_word_in_mem)[byte_offset] == 0xCC) {
                        ((unsigned char*)&current_word_in_mem)[byte_offset] = original_byte_val;
                        poke_text(aligned_addr, current_word_in_mem);
                    }
                } 
                else if (errno == ESRCH) {
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
    current_program_path_.clear(); user_program_path_display_.clear(); proc_exe_path_cached_.clear();
    entry_point_from_elf_ = 0; actual_loaded_entry_point_ = 0; base_address_ = 0; load_offset_ = 0;
    text_segment_elf_va_ = 0; text_segment_size_ = 0; text_segment_start_ = 0;
    was_stopped_at_breakpoint_addr_ = 0; status_ = 0;
    breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); next_breakpoint_id_ = 0;
    executable_regions_.clear(); in_syscall_entry_ = true;
    is_pie_or_dyn_cached_ = false;
}

long Debugger::peek_text(unsigned long long addr) {
    if (child_pid_ <= 0 || !program_loaded_) {
        return -1L;
    }
    errno = 0;
    long data = ptrace(PTRACE_PEEKTEXT, child_pid_, (void*)addr, nullptr);
    if (errno != 0) {
        if (errno == ESRCH) {
            handle_program_termination(); 
        }
        return -1L;
    }
    return data;
}

void Debugger::poke_text(unsigned long long addr, long data) {
    if (child_pid_ <= 0 || !program_loaded_) {
        return;
    }
    errno = 0;
    if (ptrace(PTRACE_POKETEXT, child_pid_, (void*)addr, (void*)data) < 0) {
        if (errno == ESRCH) {
            handle_program_termination();
        }
    }
}

void Debugger::get_registers_from_child() {
    if (child_pid_ <= 0 || !program_loaded_ ) {
        return;
    }
    if (ptrace(PTRACE_GETREGS, child_pid_, nullptr, &regs_) < 0) {
        if (errno == ESRCH) { // No such process
            handle_program_termination(); 
        }
    }
}

void Debugger::set_registers_in_child() {
    if (child_pid_ <= 0 || !program_loaded_) {
        return;
    }
    if (ptrace(PTRACE_SETREGS, child_pid_, nullptr, &regs_) < 0) {
        if (errno == ESRCH) { 
            handle_program_termination();
        }
    }
}

bool Debugger::is_address_in_executable_region(unsigned long long addr) {
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

void Debugger::refresh_executable_regions() {
    if (child_pid_ <= 0 || !program_loaded_) {
        return;
    }
    executable_regions_.clear();
    std::string maps_path = "/proc/" + std::to_string(child_pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) {
        return;
    }
    std::string line_exec_regions;
    while (std::getline(maps_file, line_exec_regions)) {
        std::stringstream ss_exec(line_exec_regions);
        std::string addr_range_exec, perms_exec;
        ss_exec >> addr_range_exec >> perms_exec;
        if (perms_exec.find('x') != std::string::npos) {
            size_t hyphen_pos_exec = addr_range_exec.find('-');
            if (hyphen_pos_exec != std::string::npos) {
                try {
                    executable_regions_.push_back({
                        hex_to_ullong(addr_range_exec.substr(0, hyphen_pos_exec)),
                        hex_to_ullong(addr_range_exec.substr(hyphen_pos_exec + 1))
                    });
                } 
                catch (...) {}
            }
        }
    }
    maps_file.close();
}

void Debugger::parse_elf_and_get_abs_entry(const char* program_file_path) {
    std::ifstream elf_file(program_file_path, std::ios::binary);
    if (!elf_file) { 
        return;
    }
    Elf64_Ehdr ehdr;
    elf_file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr)); // 讀取elf file header
    if (elf_file.gcount() != static_cast<long>(sizeof(ehdr)) || // 檢查是否讀到完整header
        !(ehdr.e_ident[EI_MAG0] == ELFMAG0 && ehdr.e_ident[EI_MAG1] == ELFMAG1 && // 驗證ELF Identification 0x7f, 'E', 'L', 'F'
          ehdr.e_ident[EI_MAG2] == ELFMAG2 && ehdr.e_ident[EI_MAG3] == ELFMAG3)) {
        elf_file.close(); 
        return;
    }
    entry_point_from_elf_ = ehdr.e_entry; // entry point offset
    is_pie_or_dyn_cached_ = (ehdr.e_type == ET_DYN);
    text_segment_elf_va_ = 0;
    text_segment_size_ = 0;
    if (ehdr.e_shoff != 0 && ehdr.e_shstrndx != SHN_UNDEF && ehdr.e_shstrndx < ehdr.e_shnum) { // ehdr.e_shstrndx : Section Header String Table Index
        elf_file.seekg(ehdr.e_shoff, std::ios::beg); // 移到Section Header Table的起始位子 (ehdr.e_shoff是 Section Header Table的offset)
        std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum); // 用來存所有section header
        elf_file.read(reinterpret_cast<char*>(shdrs.data()), ehdr.e_shnum * sizeof(Elf64_Shdr)); // read Section Header Table
        if (elf_file.gcount() == static_cast<long>(ehdr.e_shnum * sizeof(Elf64_Shdr)) &&
            shdrs[ehdr.e_shstrndx].sh_size > 0 && ehdr.e_shstrndx < shdrs.size() && shdrs[ehdr.e_shstrndx].sh_type == SHT_STRTAB) {
            std::vector<char> shstrtab_data(shdrs[ehdr.e_shstrndx].sh_size); // 用來存Section Header String Table
            elf_file.seekg(shdrs[ehdr.e_shstrndx].sh_offset, std::ios::beg); // 跳到Section Header String Table的真正位子
            elf_file.read(shstrtab_data.data(), shdrs[ehdr.e_shstrndx].sh_size);
            if (elf_file.gcount() == static_cast<long>(shdrs[ehdr.e_shstrndx].sh_size)) {
                for (const auto& sh : shdrs) {
                    if (sh.sh_name < shstrtab_data.size() && strcmp(&shstrtab_data[sh.sh_name], ".text") == 0) {  // 紀錄.text區段的位子和size
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
    std::string maps_path_for_base = "/proc/" + std::to_string(child_pid_) + "/maps";
    std::ifstream maps_file_base(maps_path_for_base);
    std::string line_map_parser_base;
    proc_exe_path_cached_.clear();
    char exe_path_buf_base[PATH_MAX + 1] = {0};
    std::string symlink_path_base = "/proc/" + std::to_string(child_pid_) + "/exe";
    ssize_t len_symlink_base = readlink(symlink_path_base.c_str(), exe_path_buf_base, PATH_MAX);
    if (len_symlink_base != -1) {
        exe_path_buf_base[len_symlink_base] = '\0'; 
        proc_exe_path_cached_ = std::string(exe_path_buf_base);
    }
    unsigned long long lowest_map_start_addr_for_exe = -1ULL;
    while(std::getline(maps_file_base, line_map_parser_base)) {
        std::stringstream ss_map_base(line_map_parser_base);
        std::string addr_range_map_base, perms_map_base, offset_str_map_base, dev_map_base, inode_str_map_base, pathname_map_base;
        ss_map_base >> addr_range_map_base >> perms_map_base >> offset_str_map_base >> dev_map_base >> inode_str_map_base;
        std::getline(ss_map_base, pathname_map_base);
        if (!pathname_map_base.empty() && pathname_map_base.front() == ' ') {
            pathname_map_base.erase(0, pathname_map_base.find_first_not_of(" "));
        }
        bool path_matches_target_base = false;
        if (!pathname_map_base.empty() &&
            (pathname_map_base == current_program_path_ || (!proc_exe_path_cached_.empty() && pathname_map_base == proc_exe_path_cached_))) {
            path_matches_target_base = true;
        }
        if(path_matches_target_base) {
            try {
                unsigned long long map_offset_base = hex_to_ullong(offset_str_map_base);
                if(map_offset_base == 0) { // 找到offset為0的區段
                    unsigned long long start_addr_map_segment_base = hex_to_ullong(addr_range_map_base.substr(0, addr_range_map_base.find('-')));  // 真正的起始位子
                    if(lowest_map_start_addr_for_exe == (unsigned long long)-1LL || start_addr_map_segment_base < lowest_map_start_addr_for_exe) {
                        lowest_map_start_addr_for_exe = start_addr_map_segment_base;
                    }
                }
            } 
            catch(...) { /* ignore errors */ }
        }
    }
    if (lowest_map_start_addr_for_exe != (unsigned long long)-1LL) {
        base_address_ = lowest_map_start_addr_for_exe;
    }
    maps_file_base.close();
    // 計算entry point的address
    if (is_pie_or_dyn_cached_) {
        actual_loaded_entry_point_ = base_address_ + entry_point_from_elf_;
        load_offset_ = base_address_;
    } 
    else {
        actual_loaded_entry_point_ = entry_point_from_elf_; 
        load_offset_ = 0;
    }
    if (text_segment_elf_va_ != 0 && text_segment_size_ != 0) { // 在elf segment header有找到.text的資訊
         text_segment_start_ = text_segment_elf_va_ + load_offset_;
    } 
    else {
        text_segment_start_ = base_address_; 
        text_segment_size_ = 0;
    }
    refresh_executable_regions();
}

void Debugger::load_program_internal(char** argv_for_exec) {
    if (program_loaded_) { 
        kill_program();
    }
    entry_point_from_elf_ = 0; actual_loaded_entry_point_ = 0; base_address_ = 0; load_offset_ = 0;
    text_segment_elf_va_ = 0; text_segment_size_ = 0; text_segment_start_ = 0; executable_regions_.clear();
    breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); next_breakpoint_id_ = 0;
    is_pie_or_dyn_cached_ = false; was_stopped_at_breakpoint_addr_ = 0;
    status_ = 0; in_syscall_entry_ = true; proc_exe_path_cached_.clear();
    memset(&regs_, 0, sizeof(regs_));
    user_program_path_display_ = argv_for_exec[0];
    char abs_program_path_buf[PATH_MAX];
    if (realpath(argv_for_exec[0], abs_program_path_buf) == NULL) {  // get absolute path
        current_program_path_ = argv_for_exec[0];
    } 
    else {
        current_program_path_ = abs_program_path_buf;
    }
    child_pid_ = fork();
    if (child_pid_ < 0) { 
        perror("** fork failed"); 
        program_loaded_ = false; 
        return; 
    }
    if (child_pid_ == 0) {
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {  // tell parent to start tracing
            perror("** ptrace(TRACEME) failed"); 
            _exit(EXIT_FAILURE); 
        }
        std::string prog_path_str = user_program_path_display_;
        size_t last_slash = prog_path_str.rfind('/');
        if (last_slash != std::string::npos) {
            std::string dir = prog_path_str.substr(0, last_slash);
            if (!dir.empty() && chdir(dir.c_str()) != 0) {
                //perror("** chdir in child failed");
            }
        }
        if (execvp(current_program_path_.c_str(), argv_for_exec) < 0) { 
            perror("** execvp failed"); 
            _exit(EXIT_FAILURE); 
        }
    } 
    else {
        if (waitpid(child_pid_, &status_, 0) < 0) { 
            perror("** waitpid failed"); 
            program_loaded_ = false; 
            child_pid_ = -1; 
            return;
        }
        if (!WIFSTOPPED(status_)) { // check if child is stopped by signal
            std::cerr << "** Program '" << user_program_path_display_ << "' failed to start or exited/signaled immediately." << std::endl;
            child_pid_ = -1; 
            program_loaded_ = false; 
            return;
        }
        // set ptrace options
        // PTRACE_O_TRACESYSGOOD : 區分是不是由syscall造成的停止
        if (ptrace(PTRACE_SETOPTIONS, child_pid_, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) < 0) {
            // perror("** ptrace(PTRACE_SETOPTIONS) failed");
        }
        program_loaded_ = true;
        parse_elf_and_get_abs_entry(current_program_path_.c_str());
        // 如果在parse_elf_and_get_abs_entry後沒有獲得actual_loaded_entry_point_
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
                    if (auxv_entry_struct.a_type == AT_NULL) { // 結束
                        break;
                    }
                }
                auxv_file.close();
            }
        }
        if (actual_loaded_entry_point_ == 0) {
            std::cerr << "** Could not determine entry point for " << user_program_path_display_ << std::endl;
            kill_program(); 
            return;
        }
        get_registers_from_child();
        // 處理rip不是在entry point的情況 (e.g. dynamic linked ELF)
        if (regs_.rip != actual_loaded_entry_point_) {
            // 獲取actual_loaded_entry_point_後的內容
            long original_word_at_target_entry = peek_text(actual_loaded_entry_point_);
            if (errno != 0 && original_word_at_target_entry == -1L) {
                std::cerr << "** Failed to read memory at calculated program entry point: 0x" << std::hex << actual_loaded_entry_point_ << std::dec << std::endl;
                kill_program();
                return;
            }
            long temp_bp_word_at_target_entry = (original_word_at_target_entry & ~0xFFL) | 0xCC; // 在entry point的地方設breakpoint
            poke_text(actual_loaded_entry_point_, temp_bp_word_at_target_entry);
            ptrace(PTRACE_CONT, child_pid_, nullptr, nullptr);
            if (waitpid(child_pid_, &status_, 0) < 0) { 
                perror("** waitpid after temp BP to entry failed");
                kill_program();
                return;
            }
            if (child_pid_ > 0 && program_loaded_) {
                poke_text(actual_loaded_entry_point_, original_word_at_target_entry); //把原本的內容恢復
            }
            else { 
                kill_program();
                return;
            }

            if (WIFSTOPPED(status_) && WSTOPSIG(status_) == SIGTRAP) {
                get_registers_from_child();
                if (regs_.rip == actual_loaded_entry_point_ + 1) {
                    regs_.rip--; 
                    set_registers_in_child();
                } 
                else if (regs_.rip != actual_loaded_entry_point_) {
                    regs_.rip = actual_loaded_entry_point_; 
                    set_registers_in_child();
                }
            } 
            else { // child不是因為 SIGTRAP 而停止
                std::cerr << "** Failed to stop at program entry point after continuing from linker." << std::endl;
                if (WIFEXITED(status_) || WIFSIGNALED(status_)) {
                    handle_program_termination(); 
                }
                else {
                    kill_program();
                }
                return;
            }
        }
        get_registers_from_child();
        was_stopped_at_breakpoint_addr_ = 0;
        std::cout << "** program '" << user_program_path_display_ << "' loaded. entry point: 0x" << std::hex << actual_loaded_entry_point_ << "." << std::dec << std::endl;
        disassemble_instructions(regs_.rip, 5);
    }
}

void Debugger::disassemble_instructions(unsigned long long start_address, int count) {
    if (!program_loaded_ || child_pid_ <= 0) {
        return;
    }

    const int MAX_INSTR_BYTES_PER_INS = 15;
    std::vector<unsigned char> instruction_bytes_buffer;
    instruction_bytes_buffer.reserve(MAX_INSTR_BYTES_PER_INS * (count + 2));
    unsigned long long current_addr_for_mem_read = start_address;
    size_t target_bytes_to_read_for_disassembly = MAX_INSTR_BYTES_PER_INS * (count + 2);

    for (size_t total_bytes_copied_to_buffer = 0; total_bytes_copied_to_buffer < target_bytes_to_read_for_disassembly; ) {
        if (child_pid_ <=0 || !program_loaded_) {
            break;
        }
        if (total_bytes_copied_to_buffer > 0 && !is_address_in_executable_region(current_addr_for_mem_read) && current_addr_for_mem_read !=0) {
            break;
        }
        unsigned long long aligned_read_addr = current_addr_for_mem_read & ~(sizeof(long)-1);
        long memory_word_data = peek_text(aligned_read_addr);
        if (errno != 0 && memory_word_data == -1L) { 
            break;
        }

        for (size_t byte_idx_in_word = 0; byte_idx_in_word < sizeof(long); ++byte_idx_in_word) {
            if (total_bytes_copied_to_buffer >= target_bytes_to_read_for_disassembly) break;
            unsigned long long actual_byte_address_in_memory = aligned_read_addr + byte_idx_in_word;
            if (actual_byte_address_in_memory < start_address && total_bytes_copied_to_buffer == 0) {
                continue;
            }
            unsigned char byte_value_from_memory = ((unsigned char*)&memory_word_data)[byte_idx_in_word];
            auto bp_iterator = breakpoints_map_.find(actual_byte_address_in_memory);
            if (bp_iterator != breakpoints_map_.end()) {
                instruction_bytes_buffer.push_back(bp_iterator->second);
            } 
            else {
                instruction_bytes_buffer.push_back(byte_value_from_memory);
            }
            total_bytes_copied_to_buffer++;
        }
        current_addr_for_mem_read = aligned_read_addr + sizeof(long);
    }

    if (instruction_bytes_buffer.empty()) {
        if (is_address_in_executable_region(start_address) || start_address == 0) { 
            if (start_address != 0) std::cout << "** failed to read instructions at 0x" << std::hex << start_address << std::dec << "." << std::endl;
        } 
        else {
            std::cout << "** the address is out of the range of the executable region." << std::endl;
        }
        return;
    }

    cs_insn *capstone_insn_array;
    size_t num_insns_disassembled_by_capstone = cs_disasm(capstone_handle_,
                                                          instruction_bytes_buffer.data(),
                                                          instruction_bytes_buffer.size(),
                                                          start_address, 0, &capstone_insn_array);
    size_t instructions_displayed_count = 0;
    bool oor_message_printed_for_current_batch = false;

    if (num_insns_disassembled_by_capstone > 0) {
        for (size_t i = 0; i < num_insns_disassembled_by_capstone && instructions_displayed_count < static_cast<size_t>(count); ++i) {
            if (!is_address_in_executable_region(capstone_insn_array[i].address) && capstone_insn_array[i].address != 0) {
                if (!oor_message_printed_for_current_batch) {
                    if (instructions_displayed_count > 0 || i == 0) {
                        std::cout << "** the address is out of the range of the executable region." << std::endl;
                        oor_message_printed_for_current_batch = true;
                    }
                }
                break; 
            }
            std::cout << "      " << std::hex << capstone_insn_array[i].address << ": " << std::dec; 
            std::stringstream bytes_ss;
            for (size_t j = 0; j < capstone_insn_array[i].size; ++j) {
                bytes_ss << std::setw(2) << std::setfill('0') << std::hex << (int)capstone_insn_array[i].bytes[j] << (j < static_cast<size_t>(capstone_insn_array[i].size) - 1 ? " " : "");
            }
            // Adjusted setw for better alignment based on sample output
            std::cout << std::left << std::setw(32) << bytes_ss.str() << " " 
                      << std::setw(9) << capstone_insn_array[i].mnemonic << " " 
                      << capstone_insn_array[i].op_str << std::endl;
            instructions_displayed_count++;
        }
        cs_free(capstone_insn_array, num_insns_disassembled_by_capstone);
    }

    if (instructions_displayed_count < static_cast<size_t>(count) && !oor_message_printed_for_current_batch) {
        unsigned long long next_addr_check = start_address;
        if (num_insns_disassembled_by_capstone > 0 && instructions_displayed_count > 0) { 
            cs_insn *temp_insn_array; // Need to re-disassemble to get the last instruction's end
            size_t temp_disassembled_count = cs_disasm(capstone_handle_, instruction_bytes_buffer.data(), instruction_bytes_buffer.size(), start_address, instructions_displayed_count, &temp_insn_array);
            if (temp_disassembled_count == instructions_displayed_count && temp_disassembled_count > 0) {
                 next_addr_check = temp_insn_array[temp_disassembled_count - 1].address + temp_insn_array[temp_disassembled_count - 1].size;
            }
            if (temp_disassembled_count > 0) cs_free(temp_insn_array, temp_disassembled_count);
        } 
        else if (instructions_displayed_count == 0 && num_insns_disassembled_by_capstone == 0 && start_address != 0) {
            next_addr_check = start_address; 
        }

        if (!is_address_in_executable_region(next_addr_check) && next_addr_check != 0 && start_address !=0) {
            if ( (instructions_displayed_count > 0) || (instructions_displayed_count == 0 && num_insns_disassembled_by_capstone == 0 && !instruction_bytes_buffer.empty()) ) { // Only print if we tried and failed for valid start
                 std::cout << "** the address is out of the range of the executable region." << std::endl;
            }
        }
    }
     std::cout << std::dec; 
}

void Debugger::handle_program_termination() {
    if (WIFEXITED(status_)) {
        std::cout << "** the target program terminated." << std::endl;
    } 
    else if (WIFSIGNALED(status_)) {
        std::cout << "** the target program terminated by signal " << strsignal(WTERMSIG(status_)) << "." << std::endl;
    }
    program_loaded_ = false; child_pid_ = -1; was_stopped_at_breakpoint_addr_ = 0;
    breakpoints_map_.clear(); breakpoint_id_to_addr_.clear(); text_segment_elf_va_ = 0; text_segment_size_ = 0;
    executable_regions_.clear(); next_breakpoint_id_ = 0; load_offset_ = 0;
    actual_loaded_entry_point_ = 0; base_address_ = 0; entry_point_from_elf_ = 0;
    text_segment_start_ = 0; in_syscall_entry_ = true;
    memset(&regs_, 0, sizeof(regs_)); 
}


void Debugger::restore_original_byte_at_bp(unsigned long long bp_addr, unsigned char original_byte) {
    if (child_pid_ <= 0 || !program_loaded_) {
        return;
    }
    unsigned long long aligned_addr = bp_addr & ~(sizeof(long) - 1);
    int byte_offset = bp_addr % sizeof(long);
    long word_val = peek_text(aligned_addr);
    if (errno == 0 && word_val != -1L) {
        if (((unsigned char*)&word_val)[byte_offset] == 0xCC) { 
            ((unsigned char*)&word_val)[byte_offset] = original_byte;
            poke_text(aligned_addr, word_val);
        }
    }
}

void Debugger::rearm_breakpoint(unsigned long long bp_addr) {
    if (child_pid_ <= 0 || !program_loaded_ || !breakpoints_map_.count(bp_addr)) return;
    unsigned long long aligned_addr = bp_addr & ~(sizeof(long) - 1);
    int byte_offset = bp_addr % sizeof(long);
    long word_val = peek_text(aligned_addr);
    if (errno == 0 && word_val != -1L) {
        ((unsigned char*)&word_val)[byte_offset] = 0xCC;
        poke_text(aligned_addr, word_val);
    }
}

void Debugger::process_breakpoint_hit(unsigned long long bp_addr) {
    if (!breakpoints_map_.count(bp_addr)) {
        return;
    }

    struct user_regs_struct temp_regs_for_set; // Use a temporary struct for SETREGS
    if (ptrace(PTRACE_GETREGS, child_pid_, nullptr, &temp_regs_for_set) < 0) {
        if (errno == ESRCH) { 
            handle_program_termination(); 
            return;
        }
        perror("** PTRACE_GETREGS in process_breakpoint_hit failed"); return;
    }

    temp_regs_for_set.rip = bp_addr; 
    if (ptrace(PTRACE_SETREGS, child_pid_, nullptr, &temp_regs_for_set) < 0) {
        if (errno == ESRCH) {
            handle_program_termination();
            return;
        }
        perror("** PTRACE_SETREGS in process_breakpoint_hit failed"); 
        return;
    }

    // Crucially, update the member regs_ AFTER SETREGS, to reflect the state accurately.
    get_registers_from_child(); // This populates this->regs_ with the state where rip = bp_addr

    std::cout << "** hit a breakpoint at 0x" << std::hex << regs_.rip << "." << std::dec << std::endl;

    unsigned char original_byte = breakpoints_map_[bp_addr];
    restore_original_byte_at_bp(bp_addr, original_byte); 
    was_stopped_at_breakpoint_addr_ = bp_addr;

    disassemble_instructions(regs_.rip, 5);
}


void Debugger::handle_wait_status() {
    if (WIFEXITED(status_) || WIFSIGNALED(status_)) {
        handle_program_termination();
        return;
    }

    if (WIFSTOPPED(status_)) {
        if (child_pid_ > 0 && program_loaded_) { refresh_executable_regions(); }
        get_registers_from_child(); 
        if (!program_loaded_) return; 

        unsigned long long current_rip_for_handler = regs_.rip;
        int stop_signal = WSTOPSIG(status_);

        if (stop_signal == SIGTRAP) {
            unsigned long long potential_bp_addr = current_rip_for_handler - 1; 
            if (breakpoints_map_.count(potential_bp_addr)) {
                process_breakpoint_hit(potential_bp_addr);
            } 
            else {
                disassemble_instructions(current_rip_for_handler, 5);
            }
        } 
        else if (stop_signal == (SIGTRAP | 0x80)) { 
            unsigned long long syscall_instr_addr = current_rip_for_handler - 2; 
            long syscall_number = regs_.orig_rax;
            if (in_syscall_entry_) {
                 std::cout << "** enter a syscall(" << std::dec << syscall_number << ") at 0x" << std::hex << syscall_instr_addr << "." << std::dec << std::endl;
            } 
            else {
                 std::cout << "** leave a syscall(" << std::dec << syscall_number << ") = " << regs_.rax << " at 0x" << std::hex << syscall_instr_addr << "." << std::dec << std::endl;
            }
            disassemble_instructions(syscall_instr_addr, 5);
        } 
        else if (stop_signal == SIGWINCH) {
            if (program_loaded_ && child_pid_ > 0) {
                ptrace(PTRACE_CONT, child_pid_, nullptr, (void*)((long)stop_signal));
                if (waitpid(child_pid_, &status_, 0) < 0 ) { 
                    if(child_pid_ > 0 && program_loaded_) { 
                        handle_program_termination();
                    } 
                }
                else if (child_pid_ > 0 && program_loaded_) { 
                    handle_wait_status();
                } 
                return;
            }
        }
        else {
            std::cout << "** Child stopped by signal " << strsignal(stop_signal) << " (SIG=" << stop_signal << ")" << std::endl;
            disassemble_instructions(current_rip_for_handler, 5);
        }
    }
}


void Debugger::step_instruction() {
    if (!program_loaded_ || child_pid_ <= 0) {
        return;
    }
    get_registers_from_child();
    unsigned long long rip_start_of_si = regs_.rip;
    unsigned long long bp_addr_stepped_off = 0;

    if (was_stopped_at_breakpoint_addr_ == rip_start_of_si && was_stopped_at_breakpoint_addr_ != 0) {
        bp_addr_stepped_off = was_stopped_at_breakpoint_addr_;
    }
    was_stopped_at_breakpoint_addr_ = 0;

    if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) {
        if (errno == ESRCH) {
            handle_program_termination();
        }
        else {
            perror("** ptrace(SINGLESTEP) failed");
        }
        return;
    }
    if (waitpid(child_pid_, &status_, 0) < 0) {
        if (errno == ESRCH) {
            handle_program_termination();
        } 
        else {
            perror("** waitpid after SINGLESTEP failed");
        }
        return;
    }

    if (bp_addr_stepped_off != 0) {
        rearm_breakpoint(bp_addr_stepped_off);
    }

    if (WIFEXITED(status_) || WIFSIGNALED(status_)) {
        handle_program_termination();
        return;
    }

    if (WIFSTOPPED(status_)) {
        get_registers_from_child();
        unsigned long long rip_after_si_step = regs_.rip;
        int stop_signal = WSTOPSIG(status_);

        if (stop_signal == SIGTRAP) {
            if (breakpoints_map_.count(rip_after_si_step) && rip_after_si_step != bp_addr_stepped_off) { // Check if RIP is directly ON a BP
                process_breakpoint_hit(rip_after_si_step);
            } 
            else if (breakpoints_map_.count(rip_after_si_step -1) && (rip_after_si_step -1) != bp_addr_stepped_off) { // Check if RIP is one byte AFTER an INT3 of a different BP
                process_breakpoint_hit(rip_after_si_step - 1);
            }
            else {
                disassemble_instructions(rip_after_si_step, 5);
            }
        } 
        else {
            handle_wait_status(); 
        }
    }
}

void Debugger::continue_execution() {
    if (!program_loaded_ || child_pid_ <= 0) return;
    get_registers_from_child();
    unsigned long long rip_at_cont_start = regs_.rip;
    unsigned long long bp_addr_stepped_off_in_cont = 0;

    if (was_stopped_at_breakpoint_addr_ == rip_at_cont_start && was_stopped_at_breakpoint_addr_ != 0) {
        bp_addr_stepped_off_in_cont = was_stopped_at_breakpoint_addr_;
        was_stopped_at_breakpoint_addr_ = 0;

        if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) {
            if (errno == ESRCH) {
                handle_program_termination();
            } 
            else {
                perror("** ptrace(SINGLESTEP) in cont failed");
            }
            return;
        }
        int temp_status;
        if (waitpid(child_pid_, &temp_status, 0) < 0) {
            if (errno == ESRCH) {
                handle_program_termination();
            } 
            else {
                perror("** waitpid after SINGLESTEP in cont failed");
            }
            return;
        }

        if (bp_addr_stepped_off_in_cont != 0) {
            rearm_breakpoint(bp_addr_stepped_off_in_cont);
        }

        status_ = temp_status;
        if (WIFEXITED(status_) || WIFSIGNALED(status_)) {
            handle_program_termination();
            return;
        }

        if (WIFSTOPPED(status_)) {
            get_registers_from_child();
            unsigned long long rip_after_first_step = regs_.rip;
            int stop_sig_first_step = WSTOPSIG(status_);

            if (stop_sig_first_step == SIGTRAP) {
                if (breakpoints_map_.count(rip_after_first_step) && rip_after_first_step != bp_addr_stepped_off_in_cont) {
                    process_breakpoint_hit(rip_after_first_step);
                    return; 
                } 
                else if (breakpoints_map_.count(rip_after_first_step-1) && (rip_after_first_step-1) != bp_addr_stepped_off_in_cont) {
                    process_breakpoint_hit(rip_after_first_step-1);
                    return;
                }
            } 
            else {
                handle_wait_status(); 
                return;
            }
        }
    } 
    else {
        was_stopped_at_breakpoint_addr_ = 0;
    }

    if (ptrace(PTRACE_CONT, child_pid_, nullptr, nullptr) < 0) {
        if (errno == ESRCH) {
            handle_program_termination();
        } 
        else {
            perror("** ptrace(CONT) failed");
        }
        return;
    }
    if (waitpid(child_pid_, &status_, 0) < 0) {
        if (errno == ESRCH) {
            handle_program_termination();
        } 
        else {
            perror("** waitpid after CONT failed");
        }
        return;
    }
    handle_wait_status(); 
}


void Debugger::handle_syscall_command() {
    if (!program_loaded_ || child_pid_ <= 0) return;
    get_registers_from_child();
    unsigned long long rip_before_cmd = regs_.rip;
    unsigned long long bp_addr_stepped_off_for_syscall = 0;

    if (was_stopped_at_breakpoint_addr_ == rip_before_cmd && was_stopped_at_breakpoint_addr_ != 0) {
        bp_addr_stepped_off_for_syscall = was_stopped_at_breakpoint_addr_;
        was_stopped_at_breakpoint_addr_ = 0;

        if (ptrace(PTRACE_SINGLESTEP, child_pid_, nullptr, nullptr) < 0) { 
            if(errno == ESRCH) {
                handle_program_termination();
            }
            return; 
        }
        int temp_status;
        if (waitpid(child_pid_, &temp_status, 0) < 0) { 
            if(errno == ESRCH) {
                handle_program_termination(); 
            }
            return; 
        }

        if (bp_addr_stepped_off_for_syscall != 0) {
            rearm_breakpoint(bp_addr_stepped_off_for_syscall);
        }
        status_ = temp_status;
        if (WIFEXITED(status_) || WIFSIGNALED(status_)) {
            handle_program_termination(); 
            return;
        }
        if (WIFSTOPPED(status_)) {
            get_registers_from_child();
        } 
        else {
            return;
        }
    } 
    else {
      was_stopped_at_breakpoint_addr_ = 0;
    }

    if (ptrace(PTRACE_SYSCALL, child_pid_, nullptr, nullptr) < 0) {
        if (errno == ESRCH) {
            handle_program_termination();
        } 
        else {
            perror("** ptrace(SYSCALL) failed");
        }
        return;
    }
    if (waitpid(child_pid_, &status_, 0) < 0) {
        if (errno == ESRCH) {
            handle_program_termination();
        } 
        else {
            perror("** waitpid after SYSCALL failed");
        }
        return;
    }

    if (WIFEXITED(status_) || WIFSIGNALED(status_)) {
        handle_program_termination(); 
        return;
    }

    if (WIFSTOPPED(status_)) {
        get_registers_from_child();
        unsigned long long rip_at_syscall_event = regs_.rip;
        int stop_signal = WSTOPSIG(status_);

        if (stop_signal == (SIGTRAP | 0x80)) {
            unsigned long long syscall_instr_addr = rip_at_syscall_event - 2;
            long syscall_number = regs_.orig_rax;
            if (in_syscall_entry_) {
                std::cout << "** enter a syscall(" << std::dec << syscall_number << ") at 0x" << std::hex << syscall_instr_addr << "." << std::dec << std::endl;
                in_syscall_entry_ = false;
            } 
            else {
                long syscall_return_value = regs_.rax;
                std::cout << "** leave a syscall(" << std::dec << syscall_number << ") = " << std::dec << syscall_return_value;
                std::cout << " at 0x" << std::hex << syscall_instr_addr << "." << std::dec << std::endl;
                in_syscall_entry_ = true;
            }
            disassemble_instructions(syscall_instr_addr, 5);
        } 
        else if (stop_signal == SIGTRAP) {
            unsigned long long potential_bp_addr = rip_at_syscall_event - 1;
            if (breakpoints_map_.count(potential_bp_addr) && potential_bp_addr != bp_addr_stepped_off_for_syscall) {
                process_breakpoint_hit(potential_bp_addr);
            } 
            else {
                 // If it's the same BP we just stepped off, or not a BP, just disassemble current location
                disassemble_instructions(rip_at_syscall_event, 5);
            }
            in_syscall_entry_ = true;
        } 
        else {
            handle_wait_status();
            in_syscall_entry_ = true;
        }
    }
}

void Debugger::print_registers() {
    if (!program_loaded_ || child_pid_ <= 0) {
        return;
    }
    if (ptrace(PTRACE_GETREGS, child_pid_, nullptr, &regs_) < 0) {
        if (errno == ESRCH) {
            handle_program_termination(); 
        } 
        else {
            perror("** ptrace(GETREGS) for print_registers failed");
        }
        return; 
    }

    char reg_print_buf[40];

    auto print_one_reg_entry = [&](const char* name, unsigned long long val, bool is_last_on_line) {
        char name_padded[10];
        strncpy(name_padded, name, 9);
        name_padded[9] = '\0';
        
        sprintf(reg_print_buf, "%-4s 0x%016llx", name, val); 
        std::cout << reg_print_buf;
        if (!is_last_on_line) {
            std::cout << "    ";
        } 
        else {
            std::cout << std::endl;
        }
    };
    
    print_one_reg_entry("$rax", regs_.rax, false); print_one_reg_entry("$rbx", regs_.rbx, false); print_one_reg_entry("$rcx", regs_.rcx, true);
    print_one_reg_entry("$rdx", regs_.rdx, false); print_one_reg_entry("$rsi", regs_.rsi, false); print_one_reg_entry("$rdi", regs_.rdi, true);
    print_one_reg_entry("$rbp", regs_.rbp, false); print_one_reg_entry("$rsp", regs_.rsp, false); print_one_reg_entry("$r8", regs_.r8, true);  
    print_one_reg_entry("$r9", regs_.r9, false);  print_one_reg_entry("$r10", regs_.r10, false); print_one_reg_entry("$r11", regs_.r11, true);
    print_one_reg_entry("$r12", regs_.r12, false); print_one_reg_entry("$r13", regs_.r13, false); print_one_reg_entry("$r14", regs_.r14, true);
    print_one_reg_entry("$r15", regs_.r15, false); print_one_reg_entry("$rip", regs_.rip, false); print_one_reg_entry("$eflags", regs_.eflags, true);
}

void Debugger::set_breakpoint_common(unsigned long long addr, bool is_rva_command) {
    if (!program_loaded_ || child_pid_ <= 0) { return; }
    bool is_valid_for_bp = is_address_in_executable_region(addr);
    if (!is_valid_for_bp && addr !=0) {
        errno = 0; 
        peek_text(addr & ~(sizeof(long)-1));
        if (errno == 0) {
            is_valid_for_bp = true;
        }
    }
    if (!is_valid_for_bp) {
        std::cout << "** the target address is not valid." << std::endl; 
        return;
    }
    for(const auto& id_addr_pair : breakpoint_id_to_addr_) {
        if(id_addr_pair.second == addr && breakpoints_map_.count(addr)) {
             std::cout << "** set a breakpoint at 0x" << std::hex << addr << "." << std::dec << std::endl;
             return;
        }
    }
    unsigned long long aligned_addr = addr & ~(sizeof(long)-1);
    int byte_offset = addr % sizeof(long);
    errno = 0;
    long current_word_val = peek_text(aligned_addr);
    if (errno != 0 && current_word_val == -1L) {
        std::cout << "** the target address is not valid." << std::endl;
        return;
    }
    unsigned char original_byte = ((unsigned char*)&current_word_val)[byte_offset];
    get_registers_from_child(); 
    breakpoints_map_[addr] = original_byte;
    breakpoint_id_to_addr_[next_breakpoint_id_] = addr;
    if (!(regs_.rip == addr && was_stopped_at_breakpoint_addr_ == addr)) {
        rearm_breakpoint(addr);
    }
    std::cout << "** set a breakpoint at 0x" << std::hex << addr << "." << std::dec << std::endl;
    next_breakpoint_id_++;
}

void Debugger::set_breakpoint(const std::string& addr_str) {
    unsigned long long addr;
    try { 
        addr = hex_to_ullong(addr_str); 
    }
    catch (const std::exception& e) { 
        std::cout << "** the target address is not valid." << std::endl; 
        return; 
    }
    set_breakpoint_common(addr, false);
}

void Debugger::set_breakpoint_rva(const std::string& offset_str) {
    unsigned long long offset;
    try { 
        offset = hex_to_ullong(offset_str); 
    }
    catch (const std::exception& e) { 
        std::cout << "** the target address is not valid." << std::endl; 
        return; 
    }
    if (base_address_ == 0 && is_pie_or_dyn_cached_) {
        if (child_pid_ > 0 && program_loaded_) {
            parse_elf_and_get_abs_entry(current_program_path_.c_str());
        }
        else { 
            std::cout << "** cannot determine base address for RVA breakpoint." << std::endl; 
            return;
        }
    }
    unsigned long long addr = base_address_ + offset;
    set_breakpoint_common(addr, true);
}

void Debugger::info_breakpoints() {
    if (!program_loaded_) { 
        std::cout << "** please load a program first." << std::endl; 
        return; 
    }
    if (breakpoint_id_to_addr_.empty()) {
        std::cout << "** no breakpoints." << std::endl; 
        return;
    }
    std::vector<std::pair<int, unsigned long long>> active_bps;
    for(const auto& pair_id_addr : breakpoint_id_to_addr_) {
        if(breakpoints_map_.count(pair_id_addr.second)) {
            active_bps.push_back(pair_id_addr);
        }
    }
    if (active_bps.empty()) {
        std::cout << "** no breakpoints." << std::endl; 
        return;
    }
    std::sort(active_bps.begin(), active_bps.end(), [](const auto&a, const auto&b) {
        return a.first < b.first;
    });
    std::cout << "Num     Address" << std::endl; 
    for (const auto& bp_info : active_bps) {
        std::cout << std::left << std::setw(8) << bp_info.first
                  << "0x" << std::hex << bp_info.second << std::dec << std::endl;
    }
}

void Debugger::delete_breakpoint(int id) {
    if (!program_loaded_ || child_pid_ <= 0) { 
        return; 
    }
    auto id_iter = breakpoint_id_to_addr_.find(id);
    if (id_iter == breakpoint_id_to_addr_.end()) {
        std::cout << "** breakpoint " << id << " does not exist." << std::endl; 
        return;
    }
    unsigned long long addr_to_delete = id_iter->second;
    auto bp_data_iter = breakpoints_map_.find(addr_to_delete);
    if (bp_data_iter == breakpoints_map_.end()) {
        breakpoint_id_to_addr_.erase(id_iter);
        std::cout << "** breakpoint " << id << " does not exist (map inconsistent)." << std::endl; 
        return;
    }
    unsigned char original_byte_to_restore = bp_data_iter->second;
    get_registers_from_child();
    if (regs_.rip != addr_to_delete || was_stopped_at_breakpoint_addr_ != addr_to_delete) {
        restore_original_byte_at_bp(addr_to_delete, original_byte_to_restore);
    }
    breakpoints_map_.erase(bp_data_iter);
    breakpoint_id_to_addr_.erase(id_iter);
    std::cout << "** delete breakpoint " << id << "." << std::endl;
    if (was_stopped_at_breakpoint_addr_ == addr_to_delete) {
        was_stopped_at_breakpoint_addr_ = 0;
    }
}

void Debugger::patch_memory(const std::string& addr_str, const std::string& hex_values_str) {
    if (!program_loaded_ || child_pid_ <= 0) { 
        return;
    }
    unsigned long long start_patch_addr;
    try { 
        start_patch_addr = hex_to_ullong(addr_str);
    }
    catch (const std::exception& e) { 
        std::cout << "** the target address is not valid." << std::endl;
        return; 
    }
    if (hex_values_str.length() % 2 != 0 || hex_values_str.length() > 2048 || hex_values_str.empty()) {
        std::cout << "** the target address is not valid." << std::endl; 
        return;
    }
    std::vector<unsigned char> bytes_to_write_to_memory;
    for (size_t i = 0; i < hex_values_str.length(); i += 2) {
        std::string byte_hex_str = hex_values_str.substr(i, 2);
        try {
            unsigned long byte_val_ul = std::stoul(byte_hex_str, nullptr, 16);
            if (byte_val_ul > 0xFF) {
                throw std::out_of_range("byte value exceeds 0xFF");
            }
            bytes_to_write_to_memory.push_back(static_cast<unsigned char>(byte_val_ul));
        }
        catch (const std::exception& e) { 
            std::cout << "** the target address is not valid." << std::endl; 
            return; 
        }
    }
    if (bytes_to_write_to_memory.empty() && !hex_values_str.empty()) {
        std::cout << "** the target address is not valid." << std::endl; 
        return;
    }
    if (!bytes_to_write_to_memory.empty()) {
        unsigned long long first_byte_aligned_addr = start_patch_addr & ~(sizeof(long)-1);
        unsigned long long last_byte_addr = start_patch_addr + bytes_to_write_to_memory.size() - 1;
        unsigned long long last_byte_aligned_addr = last_byte_addr & ~(sizeof(long)-1);
        errno = 0; 
        peek_text(first_byte_aligned_addr);
        if (errno != 0) { 
            std::cout << "** the target address is not valid." << std::endl; 
            return; 
        }
        if (bytes_to_write_to_memory.size() > 1) {
             if (last_byte_aligned_addr != first_byte_aligned_addr) {
                errno = 0; 
                peek_text(last_byte_aligned_addr);
                if (errno != 0) { 
                    std::cout << "** the target address is not valid." << std::endl; 
                    return; 
                }
             }
        }
    } 
    else {
        std::cout << "** patch memory at 0x" << std::hex << start_patch_addr << "." << std::dec << std::endl; 
        return;
    }
    for (size_t i = 0; i < bytes_to_write_to_memory.size(); ++i) {
        if (child_pid_ <=0 || !program_loaded_ ) { 
            std::cout << "** target program terminated during patch." << std::endl; 
            return; 
        }
        unsigned long long current_byte_addr_being_patched = start_patch_addr + i;
        unsigned char byte_value_for_patch = bytes_to_write_to_memory[i];
        if (breakpoints_map_.count(current_byte_addr_being_patched)) {
            breakpoints_map_[current_byte_addr_being_patched] = byte_value_for_patch;
        }
        unsigned long long word_aligned_addr_for_poke = current_byte_addr_being_patched & ~(sizeof(long)-1);
        int byte_offset_in_word_for_poke = current_byte_addr_being_patched % sizeof(long);
        errno = 0;
        long current_memory_word_val = peek_text(word_aligned_addr_for_poke);
        if (errno != 0 && current_memory_word_val == -1L) {
            std::cout << "** the target address is not valid." << std::endl; 
            return;
        }
        ((unsigned char*)&current_memory_word_val)[byte_offset_in_word_for_poke] = byte_value_for_patch;
        poke_text(word_aligned_addr_for_poke, current_memory_word_val);
        if (errno == ESRCH && child_pid_ > 0 && program_loaded_) { 
            std::cout << "** the target address is not valid." << std::endl;
            handle_program_termination(); 
            return;
        }
    }
    if (child_pid_ > 0 && program_loaded_) {
        std::cout << "** patch memory at 0x" << std::hex << start_patch_addr << "." << std::dec << std::endl;
    }
}

int main(int argc, char *argv[]) {
    Debugger sdb;
    if (argc > 1) {
        sdb.run(argv[1]);
    } 
    else {
        sdb.run();
    }
    return 0;
}