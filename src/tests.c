#include "base_types.h"
#include "util.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libdwarf/libdwarf.h>

#define PASS()                                                                                                         \
    return (struct test_result)                                                                                        \
    {                                                                                                                  \
        .name = __FUNCTION__                                                                                           \
    }

#define FAIL(msg)                                                                                                      \
    return (struct test_result)                                                                                        \
    {                                                                                                                  \
        .name = __FUNCTION__, .message = msg, .filename = __FILE__, .line = __LINE__                                   \
    }

#define TST(val, message)                                                                                              \
    if (!(val))                                                                                                        \
    FAIL(message)

#define TST_ERRNO(val) TST(val, strerror(errno))

#define TST_OP(lhs, op, rhs) TST((lhs)op(rhs), #lhs " " #op " " #rhs " is false")

#define TST_DWARF(res, dwerr) TST((res) != DW_DLV_ERROR, dwarf_errmsg(dwerr))

struct test_result {
    const char* name;
    const char* message;
    const char* filename;
    int line;
};

typedef struct test_result test_fn(void);
static void breakpoint()
{
}

static struct test_result test_debug_regs()
{
    pid_t child = fork();
    if (child < 0) {
        FAIL(strerror(errno));
    } else if (!child) {
        // In child process
        TST_ERRNO(ptrace(PTRACE_TRACEME, 0, 0, 0) != -1);

        raise(SIGSTOP);

        breakpoint();

        exit(0);
    } else {
        // in parent process
        int wstatus;

        // Wait for initial stop
        TST_ERRNO(waitpid(child, &wstatus, 0) != -1);
        TST(WIFSTOPPED(wstatus), "Child did not stop");

        // set breakpoint info
        TST_ERRNO(ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[0]), &breakpoint) != -1);
        TST_ERRNO(ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[7]), 0x2) != -1);

        // continue until breakpoint
        TST_ERRNO(ptrace(PTRACE_CONT, child, 0, 0) != -1);
        TST_ERRNO(waitpid(child, &wstatus, 0) != -1);

        // check that we're at breakpoint
        struct user_regs_struct regs;
        TST_ERRNO(ptrace(PTRACE_GETREGS, child, 0, &regs) != -1);
        TST_OP(regs.rip, ==, (uintptr_t)&breakpoint);

        // continue until exit
        TST_ERRNO(ptrace(PTRACE_CONT, child, 0, 0) != -1);
        TST_ERRNO(waitpid(child, &wstatus, 0) != -1);

        // check that we exited
        TST(waitpid(child, &wstatus, 0) == -1, "Child did not exit");
    }

    PASS();
}

static struct test_result test_dwarf()
{
    const char* program_path = "./test_child";

    char abs_path[PATH_MAX];
    TST_ERRNO(realpath(program_path, abs_path));

    printf("abs path : %s\n", abs_path);
    printf("path max : %u\n", PATH_MAX);

    Dwarf_Error dwerr = 0;
    Dwarf_Debug dbg = 0;
    int res = 0;

    // init libdwarf
    res = dwarf_init_path(program_path, 0, 0, DW_DLC_READ, DW_GROUPNUMBER_ANY, 0, 0, &dbg, 0, 0, 0, &dwerr);
    TST_DWARF(res, dwerr);

    TST(dbg, "Dwarf context is null");

    // terminate libdwarf
    res = dwarf_finish(dbg, &dwerr);
    TST_DWARF(res, dwerr);

    PASS();
}

int main(int argc, const char** argv)
{
    test_fn* test_functions[] = {
        test_debug_regs,
        test_dwarf,
    };
    uint32_t test_count = STATIC_ARRAY_COUNT(test_functions);

    uint32_t fails = 0;

    for (uint32_t i = 0; i < test_count; i++) {
        struct test_result res = test_functions[i]();

        printf("[ %3u/%u ] ", i + 1, test_count);
        if (!res.message) {
            printf("\033[32mPASSED\033[37m : %s\n", res.name);
        } else {
            printf("\033[31mFAILED\033[37m : %s at %s:%d : %s\n", res.name, res.filename, res.line, res.message);
            fails++;
        }
    }

    return fails;
}
