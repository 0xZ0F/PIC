#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>

#define PIC_SECTION_NAME "PIC"

#define PIC_START __pragma(code_seg(push, t1, PIC_SECTION_NAME))
#define PIC_END __pragma(code_seg(pop, t1))
#define PIC_DATA __declspec(allocate(PIC_SECTION_NAME))

int PIC_Strncmp(const char* str1, const char* str2, size_t len);
HMODULE GetHandleToKernel32();
void* FindExport(const char* exportName, const size_t exportNameLen);