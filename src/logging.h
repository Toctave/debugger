#pragma once

typedef enum log_severity_e {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
} log_severity_e;

typedef struct mem_allocator_i mem_allocator_i;

void log_init(mem_allocator_i* alloc);
void log_terminate();

void log_message(log_severity_e severity, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
void log_continue(const char* fmt, ...) //
    __attribute__((format(printf, 1, 2)));

void log_flush();

#define log_debug(...) log_message(DEBUG, __VA_ARGS__)
#define log_info(...) log_message(INFO, __VA_ARGS__)
#define log_warning(...) log_message(WARNING, __VA_ARGS__)
#define log_error(...) log_message(ERROR, __VA_ARGS__)
