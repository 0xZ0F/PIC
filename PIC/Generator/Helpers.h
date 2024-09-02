#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>

#define PIC_SECTION_NAME "PIC"

// Denotes functions or data that will be placed in the PIC section.
#define PIC_START __pragma(code_seg(push, t1, PIC_SECTION_NAME))

// Denotes the end of the PIC section.
#define PIC_END __pragma(code_seg(pop, t1))

// Denotes data that will be placed in the PIC section.
#define PIC_DATA __declspec(allocate(PIC_SECTION_NAME))

/// <summary>
/// Equivalent to the C standard library function strlen().
/// </summary>
/// <param name="str1"></param>
/// <param name="str2"></param>
/// <param name="len"></param>
/// <returns></returns>
int PIC_Strncmp(const char* str1, const char* str2, size_t len);

/// <summary>
/// Obtain a handle to Kernel32.dll.
/// </summary>
/// <returns>Handle to Kernel32</returns>
HMODULE GetHandleToKernel32();

/// <summary>
/// Find an export based on its name.
/// </summary>
/// <param name="exportName">Name of export to find.</param>
/// <param name="exportNameLen">Length of the export's name.</param>
/// <returns>Returns a pointer to the export if found, NULL otherwise.</returns>
void* FindExport(const char* exportName, const size_t exportNameLen);