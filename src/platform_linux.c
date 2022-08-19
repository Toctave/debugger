#include "platform.h"

#include "my_assert.h"

#include "logging.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <unistd.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

char EXECUTABLE_PATH[1024];

// source : https://forum.juce.com/t/detecting-if-a-process-is-being-run-under-a-debugger/2098
// This works on both linux and MacOSX (and any BSD kernel).
bool platform_running_under_debugger()
{
    static int underDebugger = 0;
    static bool isCheckedAlready = false;

    if (!isCheckedAlready) {
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0)
            underDebugger = 1;
        else
            ptrace(PTRACE_DETACH, 0, 1, 0);

        isCheckedAlready = true;
    }
    return underDebugger == 1;
}

void* platform_virtual_alloc(uint64_t size)
{
    void* result = mmap(0,
                        size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                        -1,
                        0);

    if (result == MAP_FAILED)
    {
        log_error("Call to mmap(%lu) failed : %s", size, strerror(errno));
        return 0;
    }

    return result;
}

void platform_virtual_free(void* ptr, uint64_t size) { munmap(ptr, size); }

uint64_t
platform_read_binary_file(void* buffer, uint64_t size, const char* path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        return 0;
    }

    ssize_t bytes_read = read(fd, buffer, size);

    if (bytes_read < 0)
    {
        close(fd);
        return 0;
    }

    close(fd);
    return bytes_read;
}

static platform_file_o* fd_to_ptr(int fd)
{
    return (platform_file_o*)((int64_t)fd + 1);
}

static int ptr_to_fd(platform_file_o* ptr) { return (int64_t)ptr - 1; }

platform_file_o* platform_open_file(const char* path)
{
    int64_t fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        return 0;
    }

    return fd_to_ptr(fd);
}

void platform_close_file(platform_file_o* file)
{
    int fd = ptr_to_fd(file);
    close(fd);
}

uint64_t platform_get_file_size(platform_file_o* file)
{
    int fd = ptr_to_fd(file);
    struct stat statbuf;

    if (fstat(fd, &statbuf) < 0)
    {
        return 0;
    }

    return statbuf.st_size;
}

uint64_t platform_read_file(platform_file_o* file, void* buffer, uint64_t size)
{
    int fd = ptr_to_fd(file);

    ssize_t bytes_read = read(fd, buffer, size);

    if (bytes_read < 0)
    {
        return 0;
    }

    return bytes_read;
}

uint64_t platform_get_nanoseconds()
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    return (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
}

void platform_get_shared_library_path(char* path,
                                      uint32_t size,
                                      const char* name)
{
    snprintf(path, size, "%s/lib%s.so", EXECUTABLE_PATH, name);
}

void* platform_open_shared_library(const char* name)
{
    char file_name[2048];
    platform_get_shared_library_path(file_name, sizeof(file_name), name);
    // TODO(octave) : check that the path isn't too long

    void* result = dlopen(file_name, RTLD_NOW | RTLD_GLOBAL);
    if (!result)
    {
        log_error("Could not open shared library '%s' : %s",
                  file_name,
                  dlerror());
    }
    return result;
}

void platform_close_shared_library(void* lib) { dlclose(lib); }

void* platform_get_symbol_address(void* lib, const char* name)
{
    return dlsym(lib, name);
}
