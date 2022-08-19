#include "logging.h"
#include "memory.h"
#include "my_assert.h"
#include "util.h"

#include "base_types.h"
#include <stdarg.h>
#include <stdio.h>

typedef struct log_message_t {
    log_severity_e severity;
    uint64_t first_line;
    uint64_t line_count;
} log_message_t;

static bool writing_message;
static char* buffer;
static char* cursor;
static uint64_t* line_indices;
static uint64_t line_count;

static log_message_t* messages;
static uint64_t message_count;

#define BUFFER_SIZE Gibi(1)

void log_init(mem_allocator_i* alloc)
{
    buffer = mem_alloc(alloc, BUFFER_SIZE);
    messages = mem_alloc(alloc, BUFFER_SIZE);
    line_indices = mem_alloc(alloc, BUFFER_SIZE);

    cursor = buffer;

    line_indices[0] = 0;
}

static const char* get_severity_string(log_severity_e severity)
{
    switch (severity)
    {
    case DEBUG:
        return "DEBUG";
    case INFO:
        return "INFO";
    case WARNING:
        return "WARNING";
    case ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

static void print_message(const log_message_t* message)
{
    int indent =
        fprintf(stderr, "[%s] ", get_severity_string(message->severity));

    for (uint64_t line = message->first_line;
         line < message->first_line + message->line_count;
         line++)
    {
        char* line_text = &buffer[line_indices[line]];

        int length = line_indices[line + 1] - line_indices[line];

        if (line > message->first_line)
        {
            for (int i = 0; i < indent; i++)
            {
                fprintf(stderr, " ");
            }
        }

        fprintf(stderr, "%.*s", length, line_text);
    }
}

static void endline()
{
    *cursor++ = '\n';
    log_message_t* message = &messages[message_count - 1];
    message->line_count++;

    line_indices[++line_count] = cursor - buffer;
}

static void finish_message()
{
    ASSERT(writing_message);
    // don't add a new line if last line is empty.
    if (cursor - &buffer[line_indices[line_count]] > 0) {
        endline();
    }
    print_message(&messages[message_count - 1]);

    writing_message = false;
}

void log_flush()
{
    if (!buffer)
    {
        return;
    }
    if (writing_message)
    {
        finish_message();
    }
}

void log_terminate()
{
    log_flush();

    platform_virtual_free(buffer, BUFFER_SIZE);
    platform_virtual_free(messages, BUFFER_SIZE);
    platform_virtual_free(line_indices, BUFFER_SIZE);
}

static void vlog_continue(const char* fmt, va_list args)
{
    if (!buffer)
    {
        fprintf(stderr, "    ");
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        return;
    }
    int length = vsprintf(cursor, fmt, args);

    for (int i = 0; i < length; i++)
    {
        if (*cursor == '\n')
        {
            endline();
        }
        else
        {
            cursor++;
        }
    }
}

static void vlog_message(log_severity_e severity, const char* fmt, va_list args)
{
    if (!buffer) {
        fprintf(stderr, "[WARNING] Logging system uninitialized\n");
        fprintf(stderr, "[%s] ", get_severity_string(severity));
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        return;
    }

    log_flush();

    ASSERT(!writing_message);
    writing_message = true;
    log_message_t* message = &messages[message_count++];

    message->severity = severity;
    message->first_line = line_count;
    message->line_count = 0;

    vlog_continue(fmt, args);
}

void log_message(log_severity_e severity, const char* fmt, ...)
{
    if (severity >= ERROR)
    {
        BREAKPOINT();
    }
    va_list args;
    va_start(args, fmt);

    vlog_message(severity, fmt, args);

    va_end(args);
}

void log_continue(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    vlog_continue(fmt, args);

    va_end(args);
}
