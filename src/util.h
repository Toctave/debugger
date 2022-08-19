#pragma once

#include "base_types.h"
#include <stdarg.h>

typedef struct mem_allocator_i mem_allocator_i;

#define Kibi(v) (1024ull * (v))
#define Mebi(v) (1024ull * Kibi(v))
#define Gibi(v) (1024ull * Mebi(v))
#define Tebi(v) (1024ull * Gibi(v))

#define Kilo(v) (1000ull * (v))
#define Mega(v) (1000ull * Kilo(v))
#define Giga(v) (1000ull * Mega(v))
#define Tera(v) (1000ull * Giga(v))

#define STATIC_ARRAY_COUNT(arr) (sizeof(arr) / sizeof(arr[0]))

#define offsetof(type, member) ((uint8_t*)(&((type*)0)->member) - (uint8_t*)0)

char* vtprintf(mem_allocator_i* stack, const char* fmt, va_list args);
char* tprintf(mem_allocator_i* stack, const char* fmt, ...);

static inline void set_bit(uint8_t* bytes, uint32_t index)
{
    uint32_t i = index / 8;
    uint32_t m = 1 << (index % 8);

    bytes[i] |= m;
}

static inline void clear_bit(uint8_t* bytes, uint32_t index)
{
    uint32_t i = index / 8;
    uint32_t m = 1 << (index % 8);

    bytes[i] &= ~m;
}

static inline bool get_bit(uint8_t* bytes, uint32_t index)
{
    uint32_t i = index / 8;
    uint32_t m = 1 << (index % 8);

    return bytes[i] & m;
}
