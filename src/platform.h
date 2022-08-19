#pragma once

#include "base_types.h"

extern char EXECUTABLE_PATH[1024];

typedef struct mem_allocator_i mem_allocator_i;

enum {
    MOUSE_BUTTON_LEFT = 1 << 0,
    MOUSE_BUTTON_MIDDLE = 1 << 1,
    MOUSE_BUTTON_RIGHT = 1 << 2,
};

#define KEYBOARD_BITFIELD_BYTES ((KEY_COUNT - 1) / 8 + 1)

typedef struct platform_file_o platform_file_o;

bool platform_init(const char* argv0);
bool platform_running_under_debugger();

void* platform_virtual_alloc(uint64_t size);
void platform_virtual_free(void* ptr, uint64_t size);

platform_file_o* platform_open_file();
void platform_close_file(platform_file_o* file);

uint64_t platform_get_file_size(platform_file_o* file);
uint64_t platform_read_file(platform_file_o* file, void* buffer, uint64_t size);

uint64_t platform_get_nanoseconds();

char* platform_get_relative_path(mem_allocator_i* alloc, const char* name);
void platform_get_shared_library_path(char* path,
                                      uint32_t size,
                                      const char* name);
void* platform_open_shared_library(const char* path);
void platform_close_shared_library(void* lib);

void* platform_get_symbol_address(void* lib, const char* name);

