// https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c
// https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
// https://github.com/rainerzufalldererste/windows_x64_shellcode_template

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdint.h>

#include "PIC.h"

typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, const char*);
typedef HMODULE(WINAPI* LoadLibraryA_t)(const char*);
typedef void(WINAPI* ExitProcess_t)(uint32_t);
typedef int32_t(WINAPI* MessageBoxA_t)(HWND, const char*, const char*, uint32_t);

PIC_START

int PIC_Strncmp(const char* str1, const char* str2, size_t len)
{
	for(size_t i = 0; i < len; ++i)
	{
		if(str1[i] != str2[i])
		{
			return str1[i] - str2[i];
		}
	}
	return 0;
}

HMODULE GetHandleToKernel32()
{
	PEB* pPEB = (PEB*)__readgsqword(0x60);
	LDR_DATA_TABLE_ENTRY* pTableEntry = CONTAINING_RECORD(pPEB->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pTableEntry->DllBase;
	return (HMODULE)pDosHeader;
}

void* FindExport(const char* exportName, const size_t exportNameLen)
{
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)GetHandleToKernel32();
	IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((size_t)pDosHeader + pDosHeader->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pExports = (IMAGE_EXPORT_DIRECTORY*)((size_t)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	UINT* pExportNameOffsets = (UINT*)((size_t)pDosHeader + pExports->AddressOfNames);

	size_t funcIndex = 0;
	while(PIC_Strncmp((char*)((size_t)pDosHeader + pExportNameOffsets[funcIndex]), exportName, exportNameLen) != 0 && funcIndex < pExports->NumberOfFunctions)
	{
		++funcIndex;
	}

	if(funcIndex == pExports->NumberOfFunctions)
	{
		return NULL;
	}

	int16_t* pOrdinalsOffsets = (int16_t*)((size_t)pDosHeader + pExports->AddressOfNameOrdinals);
	int32_t* pFunctionOffsets = (int32_t*)((size_t)pDosHeader + pExports->AddressOfFunctions);
	return (void*)((size_t)pDosHeader + pFunctionOffsets[pOrdinalsOffsets[funcIndex]]);
}
PIC_END

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

int main()
{
	PIC();
	return 0;
}