#include <stdio.h>
#include <wchar.h>

#include <Windows.h>
#include <TlHelp32.h>

#define PROC_NAME L"Examples.exe"

DWORD GetPidByProcessName(WCHAR* name) {
	PROCESSENTRY32W entry;
	memset(&entry, 0, sizeof(entry));
	entry.dwSize = sizeof(PROCESSENTRY32W);

	DWORD pid = -1;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32FirstW(hSnapShot, &entry)) {
		do {
			if (!wcscmp(name, entry.szExeFile)) {
				pid = entry.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnapShot, &entry));
	}

	CloseHandle(hSnapShot);
	return pid;
}

bool ScanMemory(HANDLE hProcess) {
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	
	LPVOID lpStartAddress = (LPVOID)sysinfo.lpMinimumApplicationAddress;
	LPVOID lpEndAddress = (LPVOID)sysinfo.lpMaximumApplicationAddress;

	while (lpStartAddress < lpEndAddress) {
		MEMORY_BASIC_INFORMATION mbi = { 0, };
		if (!VirtualQueryEx(hProcess, lpStartAddress, &mbi, sizeof(mbi))) {
			return false;
		}

		if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && mbi.Protect != PAGE_NOACCESS) {
			if ((mbi.Protect & PAGE_READONLY) || (mbi.Protect & PAGE_READWRITE)
				|| (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE))
			{
				printf("%p\n", lpStartAddress);
			}
		}

		lpStartAddress = (LPVOID)((SIZE_T)lpStartAddress + mbi.RegionSize);
	}

	return true;
}

int main() {
	DWORD pid = GetPidByProcessName(PROC_NAME);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	ScanMemory(hProcess);
}
