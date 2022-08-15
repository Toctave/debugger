#define _GNU_SOURCE
#include <link.h>

#include <signal.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <libdwarf/libdwarf.h>

#include <unistd.h>

#define pt(command, addr, data)                                                                                        \
    do {                                                                                                               \
        err = ptrace(PTRACE_##command, pid, addr, data);                                                               \
        if (err == -1) {                                                                                               \
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

static int elf_offset_callback(struct dl_phdr_info* info, size_t size, void* data)
{
    unsigned long long* rip = (unsigned long long*)data;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)* hdr = &info->dlpi_phdr[i];

        if (hdr->p_type == PT_LOAD) {
            ElfW(Addr) begin = info->dlpi_addr + hdr->p_vaddr;
            ElfW(Addr) end = begin + hdr->p_memsz;
            if (*rip >= begin && *rip < end) {
                *rip = hdr->p_vaddr + *rip - begin;
                return 1;
            }
        }
    }
    return 0;
}

static unsigned long long get_elf_offset(unsigned long long rip)
{
    if (dl_iterate_phdr(elf_offset_callback, &rip)) {
        return rip;
    } else {
        return 0;
    }
}

static int get_elf_offset_from_maps(pid_t pid, unsigned long long int rip, unsigned long long int* addr)
{
    char map_file_name[512];
    snprintf(map_file_name, sizeof(map_file_name), "/proc/%u/maps", pid);

    FILE* map_file = fopen(map_file_name, "r");
    if (!map_file) {
        return 1;
    }

    int res = 1;
    char line[512];
    while (fgets(line, sizeof(line), map_file)) {
        unsigned long long begin, end, offset;
        char path[512];
        sscanf(line, "%llx-%llx %*s %llx %*s %*s %s", &begin, &end, &offset, path);
        if (rip >= begin && rip < end) {
            if (!strcmp(path, "/home/toc/dev/debugger/build/Debug/child")) {
                *addr = offset + rip - begin;
                res = 0;
            }
        }
    }

    fclose(map_file);
    return res;
}

static int rip_info(pid_t pid, Dwarf_Debug dbg, unsigned long long int rip, Dwarf_Error* dwerr)
{
    int res = 0;

    res = get_elf_offset_from_maps(pid, rip, &rip);
    if (res) {
        return DW_DLV_NO_ENTRY;
    }

    Dwarf_Arange* aranges = 0;
    Dwarf_Unsigned arange_count = 0;
    res = dwarf_get_aranges(dbg, &aranges, &arange_count, dwerr);
    if (res)
        return res;

    Dwarf_Arange current_arange;
    res = dwarf_get_arange(aranges, arange_count, rip, &current_arange, dwerr);
    if (res)
        return res;

    Dwarf_Off cu_die_offset;
    res = dwarf_get_cu_die_offset(current_arange, &cu_die_offset, dwerr);
    if (res)
        return res;

    Dwarf_Die die;
    res = dwarf_offdie(dbg, cu_die_offset, &die, dwerr);
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
        if (addr > rip) {
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
        dwarf_srclines_dealloc(dbg, linebuf, line_count);
    if (lines)
        dwarf_srclines_dealloc_b(lines);

    return res;
}

static int debugger_loop(pid_t pid, const char* program_path)
{
    int err = 0;
    int wstatus = 0;
    err = waitpid(pid, &wstatus, 0);

    Dwarf_Error dwerr = 0;
    Dwarf_Debug dbg = 0;
    int res = dwarf_init_path(program_path, 0, 0, DW_DLC_READ, DW_GROUPNUMBER_ANY, 0, 0, &dbg, 0, 0, 0, &dwerr);
    DWERRCHECK;

    while (WIFSTOPPED(wstatus)) {
        struct user_regs_struct regs;
        pt(GETREGS, 0, &regs);

        res = rip_info(pid, dbg, regs.rip, &dwerr);
        DWERRCHECK;

        pt(SINGLESTEP, 0, 0);

        err = waitpid(pid, &wstatus, 0);
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

    int err = 0;

    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("In call to fork");
        return 1;
    } else if (child_pid) {
        return debugger_loop(child_pid, argv[1]);
    } else {
        err = ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (err == -1) {
            perror("In call to ptrace_traceme");
            return 1;
        }

        char* const cargv[] = {argv[1], 0};
        char* const cenvp[] = {0};
        err = execve(cargv[0], cargv, cenvp);
        if (err == -1) {
            perror("In call to execve");
            return 1;
        }
        return 0;
    }
}
