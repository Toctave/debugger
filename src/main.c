#define _GNU_SOURCE
#include <link.h>

#include <signal.h>

#include "my_assert.h"
#include "util.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <libdwarf/libdwarf.h>

#include <unistd.h>

#define pt(command, addr, data)                                                                                        \
    do {                                                                                                               \
        int err = ptrace(PTRACE_##command, dbg->pid, addr, data);                                                      \
        if (err == -1 && errno) {                                                                                      \
            perror("In call to PTRACE_" #command);                                                                     \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define DWERRCHECK                                                                                                     \
    do {                                                                                                               \
        if (res != DW_DLV_OK) {                                                                                        \
            switch (res) {                                                                                             \
            case DW_DLV_ERROR: {                                                                                       \
                char* msg = dwarf_errmsg(dwerr);                                                                       \
                fprintf(stderr, "Libdwarf error : %s\n", msg);                                                         \
                return 1;                                                                                              \
            }                                                                                                          \
            case DW_DLV_NO_ENTRY: {                                                                                    \
                /*fprintf(stderr, "Libdwarf error : no entry\n");*/                                                    \
            }                                                                                                          \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

enum BreakpointCondition {
    BREAK_SLOT_USED = 0x01,
    BREAK_READ = 0x02,
    BREAK_WRITE = 0x04,
    BREAK_EXECUTION = 0x08,
    BREAK_DISABLED = 0x10,
};

struct breakpoint {
    unsigned long long address;
    uint32_t flags;
};

struct memory_mapping {
    unsigned long long begin;
    unsigned long long end;
    unsigned long long offset;
    char* path;
};

struct debugger {
    Dwarf_Debug dwarf;
    pid_t pid;
    char abs_path[PATH_MAX];
    int wstatus;

    struct breakpoint breakpoints[4]; // Use only HW breakpoints for now
    char mapping_path_buffer[8096];

    unsigned int mapping_count;
    struct memory_mapping mappings[32];
};

static int update_memory_mappings(struct debugger* dbg)
{
    char map_file_name[64];
    snprintf(map_file_name, sizeof(map_file_name), "/proc/%u/maps", dbg->pid);

    FILE* map_file = fopen(map_file_name, "r");
    if (!map_file) {
        return 1;
    }

    int res = 1;
    char line[4096];
    dbg->mapping_count = 0;
    unsigned buf_offset = 0;
    while (fgets(line, sizeof(line), map_file)) {
        // TODO(octave) : check for overflows
        struct memory_mapping* mapping = &dbg->mappings[dbg->mapping_count++];
        mapping->path = &dbg->mapping_path_buffer[buf_offset];

        int path_start, path_end;
        int matched = sscanf(line,
                             "%llx-%llx %*s %llx %*s %*s %n%s%n",
                             &mapping->begin,
                             &mapping->end,
                             &mapping->offset,
                             &path_start,
                             mapping->path,
                             &path_end);
        if (matched == 4) {
            buf_offset += path_end - path_start + 1;
        } else if (matched == 3) {
            mapping->path[0] = '\0';
            buf_offset++;
        } else {
            dbg->mapping_count = 0;

            log_error("Couldn't parse map file line %s", line);
            fclose(map_file);
            return 1;
        }
    }

    fclose(map_file);
    return 0;
}

static int pc_to_elf_address(struct debugger* dbg, unsigned long long int pc, unsigned long long int* addr)
{
    // TODO(octave) : check for overlap
    update_memory_mappings(dbg);
    for (unsigned i = 0; i < dbg->mapping_count; i++) {
        const struct memory_mapping* map = &dbg->mappings[i];
        if (pc >= map->begin && pc < map->end && !strcmp(map->path, dbg->abs_path)) {
            *addr = map->offset + pc - map->begin;
            return 0;
        }
    }
    return 1;
}

static int elf_address_to_pc(struct debugger* dbg, unsigned long long int addr, unsigned long long int* pc)
{
    // TODO(octave) : check for overlap
    update_memory_mappings(dbg);

    for (unsigned i = 0; i < dbg->mapping_count; i++) {
        const struct memory_mapping* map = &dbg->mappings[i];
        unsigned long long size = map->end - map->begin;

        unsigned long long distance_from_begin = addr - map->offset;
        if (distance_from_begin < size && !strcmp(map->path, dbg->abs_path)) {
            *pc = map->begin + distance_from_begin;
            return 0;
        }
    }
    return 1;
}

static int add_breakpoint(struct debugger* dbg, unsigned long long address, uint32_t flags, unsigned int size)
{
    int i;
    struct breakpoint* bp = 0;
    for (i = 0; i < STATIC_ARRAY_COUNT(dbg->breakpoints); i++) {
        if (!(dbg->breakpoints[i].flags & BREAK_SLOT_USED)) {
            bp = &dbg->breakpoints[i];
        }
    }

    if (!bp) {
        return 1;
    }

    bp->flags = BREAK_SLOT_USED | flags;
    bp->address = address;

    unsigned long long pc;
    int res = elf_address_to_pc(dbg, address, &pc);
    if (!res)
        return res;

    // set breakpoint trigger type
    uint32_t trigger = flags & (BREAK_READ | BREAK_WRITE | BREAK_EXECUTION);
    uint32_t condition_flag;

    switch (trigger) {
    case BREAK_READ | BREAK_WRITE:
        condition_flag = 0x3;
        break;
    case BREAK_WRITE:
        condition_flag = 0x1;
        break;
    case BREAK_EXECUTION:
        condition_flag = 0x0;
        break;
    default:
        return 1;
    }

    uint32_t size_flag;
    switch (size) {
    case 1:
        size_flag = 0x0;
        break;
    case 2:
        size_flag = 0x1;
        break;
    case 4:
        size_flag = 0x2;
        break;
    case 8:
        size_flag = 0x3;
        break;
    default:
        return 1;
    }

    int dr7_prev = ptrace(PTRACE_PEEKUSER, dbg->pid, offsetof(struct user, u_debugreg[7]), 0);
    if (dr7_prev == -1 && errno) {
        perror("In call to PTRACE_PEEKUSER");
        return 1;
    }

    uint32_t mask = (1 << (2 * i)) // enable bit
                    | (condition_flag | size_flag << 2) << (16 + 4 * i);
    pt(POKEUSER, offsetof(struct user, u_debugreg[7]), dr7_prev | mask);

    // set breakpoint address
    pt(POKEUSER, offsetof(struct user, u_debugreg[i]), pc);

    return 0;
}

static int die_info(struct debugger* dbg, Dwarf_Off offset, unsigned long long elf_addr, Dwarf_Error* dwerr)
{
    int res = 0;

    Dwarf_Die die;
    res = dwarf_offdie(dbg->dwarf, offset, &die, dwerr);
    if (res)
        return res;

    char* name;
    res = dwarf_diename(die, &name, dwerr);
    if (res)
        return res;

    // TODO(octave) : understand what two-level line tables are
    Dwarf_Line_Context lines = 0;
    Dwarf_Unsigned lines_version;
    Dwarf_Small lines_table_count;
    res = dwarf_srclines_b(die, &lines_version, &lines_table_count, &lines, dwerr);
    if (res)
        return res;

    Dwarf_Line* linebuf = 0;
    Dwarf_Signed line_count;
    res = dwarf_srclines_from_linecontext(lines, &linebuf, &line_count, dwerr);
    if (res)
        goto cleanup;

    char* filename = 0;
    Dwarf_Unsigned line_number = 0;
    for (Dwarf_Signed i = 0; i < line_count; i++) {
        Dwarf_Addr addr;
        res = dwarf_lineaddr(linebuf[i], &addr, dwerr);
        if (res)
            goto cleanup;
        if (addr > elf_addr) {
            break;
        }
        res = dwarf_linesrc(linebuf[i], &filename, dwerr);
        if (res)
            goto cleanup;
        res = dwarf_lineno(linebuf[i], &line_number, dwerr);
        if (res)
            goto cleanup;
    }

    printf("%s:%llu\n", filename, line_number);

cleanup:
    if (linebuf)
        dwarf_srclines_dealloc(dbg->dwarf, linebuf, line_count);
    if (lines)
        dwarf_srclines_dealloc_b(lines);

    return 0;
}

static int rip_info(struct debugger* dbg, unsigned long long int rip, Dwarf_Error* dwerr)
{
    int res = 0;

    unsigned long long elf_addr;

    res = pc_to_elf_address(dbg, rip, &elf_addr);
    if (res) {
        return DW_DLV_NO_ENTRY;
    }

    // Find the current address range from the instruction pointer
    Dwarf_Arange* aranges = 0;
    Dwarf_Unsigned arange_count = 0;
    res = dwarf_get_aranges(dbg->dwarf, &aranges, &arange_count, dwerr);
    if (res)
        return res;

    Dwarf_Arange current_arange;
    res = dwarf_get_arange(aranges, arange_count, elf_addr, &current_arange, dwerr);
    if (res)
        return res;

    // Get the DIE related to the current arange
    Dwarf_Off cu_die_offset;
    res = dwarf_get_cu_die_offset(current_arange, &cu_die_offset, dwerr);
    if (res)
        return res;

    res = die_info(dbg, cu_die_offset, elf_addr, dwerr);
    if (res)
        return res;

    return res;
}

void dwarf_print(void* user, const char* txt)
{
    puts(txt);
}

static int debugger_init(struct debugger* dbg, char* const exec_path)
{
    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("In call to fork");
        return 1;
    } else if (child_pid) { // In debugger
        dbg->pid = child_pid;
        realpath(exec_path, dbg->abs_path);

        int err = 0;
        err = waitpid(dbg->pid, &dbg->wstatus, 0);

        Dwarf_Error dwerr = 0;
        int res =
            dwarf_init_path(dbg->abs_path, 0, 0, DW_DLC_READ, DW_GROUPNUMBER_ANY, 0, 0, &dbg->dwarf, 0, 0, 0, &dwerr);
        DWERRCHECK;

        // setup dwarf printf
        struct Dwarf_Printf_Callback_Info_s cb = {};
        cb.dp_fptr = dwarf_print;
        dwarf_register_printf_callback(dbg->dwarf, &cb);

        return 0;
    } else { // In child process
        int err = ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (err == -1) {
            perror("In call to ptrace_traceme");
            return 1;
        }

        char* const cargv[] = {exec_path, 0};
        char* const cenvp[] = {0};
        err = execve(cargv[0], cargv, cenvp);
        if (err == -1) {
            perror("In call to execve");
            return 1;
        }
    }
}

static int debugger_loop(struct debugger* dbg)
{
    while (WIFSTOPPED(dbg->wstatus)) {
        struct user_regs_struct regs;
        pt(GETREGS, 0, &regs);

        Dwarf_Error dwerr = 0;
        int res = rip_info(dbg, regs.rip, &dwerr);
        DWERRCHECK;

        pt(SINGLESTEP, 0, 0);

        int err = waitpid(dbg->pid, &dbg->wstatus, 0);
        if (err == -1) {
            perror("In call to waitpid");
            return 1;
        }
    }

    return 0;
}

int main(int argc, char* const argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage : ./debugger <program>\n");
        return 1;
    }

    struct debugger dbg = {};

    if (debugger_init(&dbg, argv[1])) {
        return 1;
    }

    if (debugger_loop(&dbg)) {
        return 1;
    }

    return 0;
}
