#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

using GetProcAddress_t = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);

using LoadLibraryA_t = HINSTANCE(WINAPI*)(const char* lpLibFilename);

using DllEntryPoint_t = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using RtlAddFunctionTable_t = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

struct ManualMappingData
{
	BYTE* pBase;
	HINSTANCE hModule;
	DWORD fdwReason;
	LPVOID pReserved;
	LoadLibraryA_t pLoadLibraryA;
	GetProcAddress_t pGetProcAddress;
#ifdef _WIN64
	RtlAddFunctionTable_t pRtlAddFunctionTable;
#endif
};

bool InsertD11(HANDLE hProcess, BYTE* pSourceData, SIZE_T fileSize, bool clearHeader = true, bool clearNonNeededSections = true, bool adjustProtections = true, DWORD fdwReason = DLL_PROCESS_ATTACH, LPVOID lpReserved = nullptr);

void __stdcall Shellcode(ManualMappingData* pData);
