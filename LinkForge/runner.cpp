#include "runner.h"

// Disable output
#define DISABLE_OUTPUT

#if defined(DISABLE_OUTPUT)
#define PrintLog(data, ...)
#else
#define PrintLog(text, ...) printf(text, __VA_ARGS__);
#endif

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

bool InsertD11(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections, DWORD fdwReason, LPVOID lpReserved) {
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) {
		PrintLog("File is not a valid PE file\n");
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	if (pOldFileHeader->Machine != CURRENT_ARCH) {
		PrintLog("File architecture doesn't match current architecture\n");
		return false;
	}

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pTargetBase) {
		PrintLog("Can't allocate memory in target process: 0x%X\n", GetLastError());
		return false;
	}

	DWORD oldp = 0;
	VirtualProtectEx(hProc, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

	ManualMappingData data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
	data.pRtlAddFunctionTable = (RtlAddFunctionTable_t)RtlAddFunctionTable;
#else 
	SEHExceptionSupport = false;
#endif
	data.pBase = pTargetBase;
	data.fdwReason = fdwReason;
	data.pReserved = lpReserved;


	if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) {
		PrintLog("Can't write PE header: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				PrintLog("Can't write section: %s: 0x%X\n", pSectionHeader->Name, GetLastError());
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(ManualMappingData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!MappingDataAlloc) {
		PrintLog("Can't allocate memory for mapping data: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(ManualMappingData), nullptr)) {
		PrintLog("Can't write mapping data: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		PrintLog("Can't allocate memory for shellcode: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
		PrintLog("Can't write shellcode: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	//PrintLog("Mapped DLL at %p\n", pTargetBase);
	//PrintLog("Mapping info at %p\n", MappingDataAlloc);
	//PrintLog("Shell code at %p\n", pShellcode);

	//PrintLog("Data allocated\n");

#ifdef _DEBUG
	//PrintLog("My shellcode pointer %p\n", Shellcode);
	//PrintLog("Target point %p\n", pShellcode);
	system("pause");
#endif

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
	if (!hThread) {
		PrintLog("Can't create remote thread: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(hThread);

	//PrintLog("Thread created at: %p, waiting for return...\n", pShellcode);

	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		DWORD exitcode = 0;
		GetExitCodeProcess(hProc, &exitcode);
		if (exitcode != STILL_ACTIVE) {
			PrintLog("Process exited. Exit code: %d\n", exitcode);
			return false;
		}

		ManualMappingData data_checked{ 0 };
		ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hModule;

		if (hCheck == (HINSTANCE)0x333333) {
			PrintLog("Error: Shellcode failed!\n");
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
			return false;
		}
		else if (hCheck == (HINSTANCE)0x444444) {
			PrintLog("Warning: Shellcode returned NULL\n");
		}

		Sleep(15);
	}

	BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
	if (emptyBuffer == nullptr) {
		PrintLog("Can't allocate memory for empty buffer\n");
		return false;
	}
	memset(emptyBuffer, 0, 1024 * 1024 * 20);

	if (ClearHeader) {
		if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
			PrintLog("Warning: Can't clear PE header: 0x%X\n", GetLastError());
		}
	}

	if (ClearNonNeededSections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				if (strcmp((char*)pSectionHeader->Name, ".pdata") == 0 ||
					strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
					strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
					if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
						PrintLog("Can't clear section: %s: 0x%X\n", pSectionHeader->Name, GetLastError());
					}
				}
			}
		}
	}

	if (AdjustProtections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				DWORD old = 0;
				DWORD newP = PAGE_READONLY;

				if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
					newP = PAGE_READWRITE;
				}
				else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
					newP = PAGE_EXECUTE_READ;
				}
				if (VirtualProtectEx(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
					// PrintLog("Section %s permissions changed to %lX\n", (char*)pSectionHeader->Name, newP);
				}
				else {
					PrintLog("Failed to change section %s permissions to %lX: 0x%X\n", (char*)pSectionHeader->Name, newP, GetLastError());
				}
			}
		}
		DWORD old = 0;
		VirtualProtectEx(hProc, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
	}

	if (!WriteProcessMemory(hProc, pShellcode, emptyBuffer, 0x1000, nullptr)) {
		PrintLog("Warning: Can't clear shellcode: 0x%X\n", GetLastError());
	}
	if (!VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE)) {
		PrintLog("Warning: Can't free shellcode memory: 0x%X\n", GetLastError());
	}
	if (!VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE)) {
		PrintLog("Warning: Can't free mapping data memory: 0x%X\n", GetLastError());
	}

	// Free the buffer
	free(emptyBuffer);
	return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(ManualMappingData* pData) {
	if (!pData) {
		pData->hModule = reinterpret_cast<HINSTANCE>(0x333333);
		return;
	}

	BYTE* pBase = pData->pBase;
	auto* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
	auto* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDosHeader->e_lfanew);
	auto& optHeader = pNtHeaders->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<DllEntryPoint_t>(pBase + optHeader.AddressOfEntryPoint);
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif

	BYTE* locationDelta = pBase - optHeader.ImageBase;
	if (locationDelta && optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

		while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
			UINT numEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i < numEntries; ++i, ++pRelativeInfo) {
				if (RELOC_FLAG(*pRelativeInfo)) {
					auto* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(locationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if (optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDescr->Name) {
			HINSTANCE hDll = _LoadLibraryA(reinterpret_cast<char*>(pBase + pImportDescr->Name));
			if (!hDll) {
				++pImportDescr;
				continue;
			}

			auto* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			auto* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);
			if (!pThunkRef) pThunkRef = pFuncRef;

			while (*pThunkRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + *pThunkRef);
					*pFuncRef = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, pImport->Name));
				}
				++pThunkRef;
				++pFuncRef;
			}
			++pImportDescr;
		}
	}

	if (optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto** pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

		while (pCallback && *pCallback) {
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
			++pCallback;
		}
	}

	_DllMain(pBase, pData->fdwReason, pData->pReserved);

	pData->hModule = reinterpret_cast<HINSTANCE>(pBase);
}
