#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

#include <vector>

#define PROC_NAME L""
#define DLL_NAME L""

DWORD GetPidByProcessName(WCHAR *wProcName) {
	DWORD dwPid = -1;
	PROCESSENTRY32W entry;
	memset(&entry, 0, sizeof(entry));
	entry.dwSize = sizeof(entry);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32FirstW(hSnapshot, &entry)) {
		do {
			if (!_wcsicmp(PROC_NAME, entry.szExeFile)) {
				dwPid = entry.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnapshot, &entry));
	}

	CloseHandle(hSnapshot);

	return dwPid;
}

DWORD GetTidsByPid(DWORD dwPid, std::vector<DWORD>& tids) {
	THREADENTRY32 entry;
	memset(&entry, 0, sizeof(entry));
	entry.dwSize = sizeof(entry);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (Thread32First(hSnapshot, &entry)) {
		do {
			if (dwPid == entry.th32OwnerProcessID) {
				tids.push_back(entry.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &entry));
	}

	CloseHandle(hSnapshot);

	if (tids.size() > 0) {
		return 0;
	}

	return -1;
}

int main() {
	std::vector<DWORD> tids;
	DWORD dwPid = GetPidByProcessName(PROC_NAME);
	DWORD result = GetTidsByPid(dwPid, tids);

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	PAPCFUNC pLoadLibrary = (PAPCFUNC)GetProcAddress(hKernel32, "LoadLibraryW");

	SIZE_T dwSize = (wcslen(DLL_NAME) + 1) * 2;
	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPid);

	SIZE_T written = 0;
	LPVOID lpAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, lpAddress, DLL_NAME, dwSize, &written);

	for (auto dwTid : tids) {
		HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, dwTid);
		if (hThread) {
			QueueUserAPC(pLoadLibrary, hThread, (ULONG_PTR)lpAddress);
			CloseHandle(hThread);
		}
	}

	VirtualFreeEx(hProcess, lpAddress, dwSize, MEM_COMMIT);
	CloseHandle(hProcess);

	return 0;
}
