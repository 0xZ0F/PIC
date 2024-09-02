#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdint.h>

#include "Helpers.h"

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