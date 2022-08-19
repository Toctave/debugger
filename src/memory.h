#pragma once

#include "base_types.h"

typedef struct mem_stack_o mem_stack_o;

typedef struct mem_allocator_i
{
    void* impl;
    void* (*realloc)(void* impl,
                     void* ptr,
                     uint64_t old_size,
                     uint64_t new_size,
                     const char* filename,
                     uint32_t line_number);
} mem_allocator_i;

extern mem_allocator_i* mem_std_alloc;  // C standard lib allocator
extern mem_allocator_i* mem_vm_alloc;   // Virtual Memory allocator
extern mem_allocator_i*
    mem_scratch_alloc; /* // temporary stack, uses VM memory, cleared regularly */

void mem_init();
void mem_terminate();

mem_stack_o* mem_stack_create(void* buffer, uint64_t size);
void mem_stack_destroy(mem_stack_o* stack);
uint64_t mem_stack_get_cursor(mem_stack_o* stack);
void mem_stack_revert(mem_stack_o* stack, uint64_t cursor);
void* mem_stack_push(mem_stack_o* alloc, uint64_t size);

#define mem_alloc(a, size)                                                     \
    ((a)->realloc((a)->impl, 0, 0, size, __FILE__, __LINE__))
#define mem_free(a, ptr, size)                                                 \
    ((a)->realloc((a)->impl, ptr, size, 0, __FILE__, __LINE__))
#define mem_realloc(a, ptr, old_size, new_size)                                \
    ((a)->realloc((a)->impl, ptr, old_size, new_size, __FILE__, __LINE__))

