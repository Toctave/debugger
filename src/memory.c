#include "memory.h"

#include "my_assert.h"
#include "platform.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

#define MAX_ALIGNMENT 8
#define SCRATCH_ALLOC_SIZE Gibi(1)

struct mem_stack_o {
    void* base;
    uint64_t size;
    uint64_t used;
};

static mem_stack_o* scratch_stack;
static void* scratch_buffer;

static void* std_realloc(void* impl,
                         void* ptr,
                         uint64_t old_size,
                         uint64_t new_size,
                         const char* filename,
                         uint32_t line_number);
static void* vm_realloc(void* impl,
                        void* ptr,
                        uint64_t old_size,
                        uint64_t new_size,
                        const char* filename,
                        uint32_t line_number);
static void* scratch_realloc(void* impl,
                             void* ptr,
                             uint64_t old_size,
                             uint64_t new_size,
                             const char* filename,
                             uint32_t line_number);

static mem_allocator_i vm = {.impl = 0, .realloc = vm_realloc};
static mem_allocator_i std = {.impl = 0, .realloc = std_realloc};
static mem_allocator_i scratch = {.impl = 0, .realloc = scratch_realloc};

mem_allocator_i* mem_std_alloc = &std;
mem_allocator_i* mem_vm_alloc = &vm;
mem_allocator_i* mem_scratch_alloc = &scratch;

void mem_init()
{
    scratch_buffer = mem_alloc(mem_vm_alloc, SCRATCH_ALLOC_SIZE);
    scratch_stack = mem_stack_create(scratch_buffer, SCRATCH_ALLOC_SIZE);
    scratch.impl = scratch_stack;
}

void mem_terminate()
{
    mem_stack_destroy(scratch_stack);
    mem_free(mem_vm_alloc, scratch_buffer, SCRATCH_ALLOC_SIZE);
}

static void*
std_realloc(void* impl, void* ptr, uint64_t old_size, uint64_t new_size, const char* filename, uint32_t line_number)
{
    (void)old_size;
    (void)filename;
    (void)line_number;
    ASSERT(!impl);
    return realloc(ptr, new_size);
}

static void* vm_realloc(void* impl,
                        void* ptr,
                        uint64_t old_size,
                        uint64_t new_size,
                        const char* filename,
                        uint32_t line_number)
{
    ASSERT(!impl);
    (void)filename;
    (void)line_number;

    void* new_ptr = 0;
    if (new_size)
    {
        new_ptr = platform_virtual_alloc(new_size);
    }

    if (ptr)
    {
        uint64_t copy_size = old_size < new_size ? old_size : new_size;
        memcpy(new_ptr, ptr, copy_size);

        platform_virtual_free(ptr, old_size);
    }

    return new_ptr;
}

static void* scratch_realloc(void* impl,
                             void* ptr,
                             uint64_t old_size,
                             uint64_t new_size,
                             const char* filename,
                             uint32_t line_number)
{
    (void)ptr;
    (void)filename;
    (void)line_number;

    mem_stack_o* stack = impl;
    if (new_size)
    {
        void* new = mem_stack_push(stack, new_size);
        return new;
    }

    if (old_size == 0)
    {
        ASSERT(!ptr);
        // new and old = 0, signal to free everything
        mem_stack_revert(stack, 0);
    }

    return 0;
}

static void* align_up(void* ptr, uint64_t alignment)
{
    uint64_t addr = (uint64_t)ptr;
    uint64_t aligned = alignment * ((addr + alignment - 1) / alignment);

    return (void*)aligned;
}

static void* shift_up(void* ptr, uint64_t bytes)
{
    uint64_t addr = (uint64_t)ptr;

    return (void*)(addr + bytes);
}

static void* shift_align_up(void* ptr, uint64_t bytes, uint64_t alignment)
{
    return align_up(shift_up(ptr, bytes), alignment);
}

mem_stack_o* mem_stack_create(void* buffer, uint64_t size)
{
    mem_stack_o* stack = buffer;

    stack->base = shift_align_up(buffer, sizeof(mem_stack_o), MAX_ALIGNMENT);
    stack->size = (uint8_t*)buffer + size - (uint8_t*)stack->base;
    stack->used = 0;

    return stack;
}

void mem_stack_destroy(mem_stack_o* stack)
{
    stack->base = 0;
    stack->size = 0;
    stack->used = 0;
}

uint64_t mem_stack_get_cursor(mem_stack_o* alloc) { return alloc->used; }

void mem_stack_revert(mem_stack_o* alloc, uint64_t cursor)
{
    ASSERT(cursor <= alloc->used);
    alloc->used = cursor;
}

void* mem_stack_push(mem_stack_o* alloc, uint64_t size)
{
    ASSERT(alloc->used + size < alloc->size);
    void* result = (uint8_t*)alloc->base + alloc->used;

    alloc->used += size;

    return result;
}
