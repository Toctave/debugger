#include "base_types.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

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

#define TST_OP(lhs, op, rhs) TST((lhs)op(rhs), #lhs " " #op " " #rhs)

struct test_result {
    const char* name;
    const char* message;
    const char* filename;
    int line;
};

void breakpoint()
{
}

struct test_result test_debug_regs()
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

int main(int argc, const char** argv)
{
    struct test_result (*test_functions[])() = {
        test_debug_regs,
    };
    uint32_t test_count = STATIC_ARRAY_COUNT(test_functions);

    uint32_t fails = 0;

    for (uint32_t i = 0; i < test_count; i++) {
        struct test_result res = test_functions[i]();

        printf("[ %2u/%u ] %s ", i + 1, test_count, res.name);
        if (!res.message) {
            printf("\033[32mPASSED\033[37m\n");
        } else {
            printf("\033[31mFAILED\033[37m at %s:%d : %s\n", res.filename, res.line, res.message);
            fails++;
        }
    }

    return fails;
}
