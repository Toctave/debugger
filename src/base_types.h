#pragma once

#include <inttypes.h>

typedef int32_t bool;
#define true 1
#define false 0

typedef struct quad_i32_t
{
    int32_t min[2];
    int32_t extent[2];
} quad_i32_t;

typedef struct quad_float_t
{
    float min[2];
    float extent[2];
} quad_float_t;

typedef struct color_t
{
    uint8_t rgba[4];
} color_t;

typedef struct str_t
{
    uint32_t size; // in bytes, without a terminating 0
    const char* utf8;
} str_t;

quad_i32_t quad_i32_grown(quad_i32_t q, int32_t offset);
