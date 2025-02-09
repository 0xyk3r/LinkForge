#include "runner.h"

#include <vector>

// Disable output
#define DISABLE_OUTPUT

#if defined(DISABLE_OUTPUT)
#define PrintLog(data, ...)
#else
#define PrintLog(text, ...) printf(text, __VA_ARGS__);
#endif

using namespace std;

DWORD GetProcessIdByName(const wstring& name) {
	DWORD processID = 0;
	PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		PrintLog("CreateToolhelp32Snapshot Failed: 0x%X\n", GetLastError());
		return 0;
	}

	if (Process32First(snapshot, &entry)) {
		do {
			if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
				processID = entry.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return processID;
}

bool IsCorrectTargetArchitecture(HANDLE hProc) {
	BOOL isTargetWow64 = FALSE, isHostWow64 = FALSE;

	if (!IsWow64Process(hProc, &isTargetWow64)) {
		PrintLog("Can't determine target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	IsWow64Process(GetCurrentProcess(), &isHostWow64);
	return (isTargetWow64 == isHostWow64);
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
	if (argc < 2) {
		PrintLog("Usage: %s <DLL Path> [Process Name]\n", argv[0]);
		return -1;
	}
	wstring dllPath = argv[1];
	wstring processName = L"notepad.exe";
	if (argc >= 3) {
		processName = argv[2];
	}

	HANDLE hToken = nullptr;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		TOKEN_PRIVILEGES priv = {};
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)) {
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
		}

		CloseHandle(hToken);
	}

	DWORD PID = GetProcessIdByName(processName);
	if (PID == 0) {
		PrintLog("Can't find target process: %s\n", processName.c_str());
		return -2;
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc) {
		PrintLog("Can't open target process: 0x%X\n", GetLastError());
		return -3;
	}

	if (!IsCorrectTargetArchitecture(hProc)) {
		PrintLog("Can't inject into a process with different architecture\n");
		CloseHandle(hProc);
		return -4;
	}

	if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
		PrintLog("Can't find DLL file: %s\n", dllPath.c_str());
		CloseHandle(hProc);
		return -5;
	}

	ifstream file(dllPath, ios::binary | ios::ate);
	if (!file) {
		PrintLog("Can't open DLL file: %s\n", dllPath.c_str());
		CloseHandle(hProc);
		return -6;
	}

	streamsize fileSize = file.tellg();
	if (fileSize < 0x1000) {
		PrintLog("Can't inject a file smaller than 4KB\n");
		file.close();
		CloseHandle(hProc);
		return -7;
	}

	vector<BYTE> fileBuffer(fileSize);
	file.seekg(0, ios::beg);
	file.read(reinterpret_cast<char*>(fileBuffer.data()), fileSize);
	file.close();

	if (!InsertD11(hProc, fileBuffer.data(), fileSize)) {
		PrintLog("Can't inject DLL into target process\n");
		CloseHandle(hProc);
		return -8;
	}

	CloseHandle(hProc);
	return 0;
}
