#pragma once

#include "logging.h"
#include "platform.h"

#include <signal.h>

#define BREAKPOINT()                                                                                                   \
    do {                                                                                                               \
        if (platform_running_under_debugger()) {                                                                       \
            raise(SIGTRAP);                                                                                            \
        }                                                                                                              \
    } while (0)

#ifndef NO_ASSERTS

#define ASSERT_MSG(expr, message, ...)                                                                                 \
    if (!(expr)) {                                                                                                     \
        log_error("%s:%d (in '%s') : " message, __FILE__, __LINE__, __func__, __VA_ARGS__);                            \
        log_flush();                                                                                                   \
        BREAKPOINT();                                                                                                  \
        raise(SIGKILL);                                                                                                \
    }

#else

#define ASSERT_MSG(expr, message, ...)

#endif

#define ASSERT(expr) ASSERT_MSG(expr, "ASSERTion '%s' failed", #expr)

#define STRINGIFY(expr) #expr

#define ASSERT_OP(lhs, op, rhs, fmt)                                                                                   \
    ASSERT_MSG(lhs op rhs,                                                                                             \
               "ASSERTion '%s' failed with %s = " fmt " and %s = " fmt,                                                \
               STRINGIFY(lhs op rhs),                                                                                  \
               #lhs,                                                                                                   \
               lhs,                                                                                                    \
               #rhs,                                                                                                   \
               rhs)
