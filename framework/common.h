#pragma once

#include <stddef.h>

#ifdef NEOLK_PRINTF_ADDRESS
#define printf(...) ((void (*)(const char*, ...))(unsigned long long)NEOLK_PRINTF_ADDRESS)(__VA_ARGS__)
#else
void printf(const char* fmt, ...);
#endif

void* malloc(size_t n);
