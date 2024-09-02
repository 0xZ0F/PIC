/*
	Shellcode/PIC generation template.
	See the README for a more detailed explanation.
	Made by Z0F.
*/

#include "Helpers.h"

typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, const char*);
typedef HMODULE(WINAPI* LoadLibraryA_t)(const char*);
typedef void(WINAPI* ExitProcess_t)(uint32_t);
typedef int32_t(WINAPI* MessageBoxA_t)(HWND, const char*, const char*, uint32_t);

PIC_START
char PIC_DATA szLoadLibraryA[] = "LoadLibraryA";
char PIC_DATA szGetProcAddress[] = "GetProcAddress";
char PIC_DATA szMessageBoxA[] = "MessageBoxA";
char PIC_DATA szUser32[] = "user32.dll";
char PIC_DATA szHelloWorld[] = "Hello, World!";
char PIC_DATA szExitProcess[] = "ExitProcess";
DECLSPEC_NOINLINE __declspec(dllexport) void PIC()
{
	void* pGetProcAddress = FindExport(szGetProcAddress, sizeof(szGetProcAddress) + 1);
	GetProcAddress_t fpGetProcAddress = (GetProcAddress_t)FindExport(szGetProcAddress, sizeof(szGetProcAddress + 1));

	HMODULE hKernel32 = GetHandleToKernel32();
	LoadLibraryA_t fpLoadLibraryA = (LoadLibraryA_t)fpGetProcAddress(hKernel32, szLoadLibraryA);

	HMODULE user32 = fpLoadLibraryA(szUser32);

	MessageBoxA_t fpMessageBoxA = (MessageBoxA_t)fpGetProcAddress(user32, szMessageBoxA);
	fpMessageBoxA(NULL, szHelloWorld, szHelloWorld, 0);

	ExitProcess_t fpExitProcess = (ExitProcess_t)fpGetProcAddress(hKernel32, szExitProcess);
	fpExitProcess(0);
}
PIC_END