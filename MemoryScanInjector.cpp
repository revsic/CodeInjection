#include <stdio.h>
#include <wchar.h>

#include <string>
#include <vector>

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

bool ScanMemory(HANDLE hProcess, BYTE *pattern, SIZE_T length, std::vector<LPVOID>& list) {
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);

	LPVOID lpStartAddress = (LPVOID)sysinfo.lpMinimumApplicationAddress;
	LPVOID lpEndAddress = (LPVOID)sysinfo.lpMaximumApplicationAddress;

	std::string strPattern(pattern, pattern + length);

	while (lpStartAddress < lpEndAddress) {
		MEMORY_BASIC_INFORMATION mbi = { 0, };
		if (!VirtualQueryEx(hProcess, lpStartAddress, &mbi, sizeof(mbi))) {
			return false;
		}

		if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && mbi.Protect != PAGE_NOACCESS) {
			if ((mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
				BYTE *dump = new BYTE[mbi.RegionSize];
				ReadProcessMemory(hProcess, lpStartAddress, dump, mbi.RegionSize, NULL);
				std::string mem(dump, dump + mbi.RegionSize);
				
				size_t n = -1;
				while (true) {
					n = mem.find(strPattern, n + 1);
					if (n == std::string::npos) {
						break;
					}

					list.push_back((LPVOID)((SIZE_T)lpStartAddress + n));
				}

				delete[] dump;
			}
		}

		lpStartAddress = (LPVOID)((SIZE_T)lpStartAddress + mbi.RegionSize);
	}

	return true;
}

int main() {
	DWORD pid = GetPidByProcessName(PROC_NAME);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	//movsxd rcx, dword ptr ss:[rbp-40]
	//mov dword ptr ds:[rax], ecx
	//movsxd rax, dword ptr ds:[r15+50]

	std::vector<LPVOID> list;
	BYTE pattern[] = { 0x48, 0x63, 0x4D, 0xC8, 0x89, 0x08, 0x49, 0x63, 0x47, 0x50 }; //target opcode
	ScanMemory(hProcess, pattern, sizeof(pattern), list);

	BYTE code[] = { 0xC7, 0x00, 0x04, 0x00, 0x00, 0x00 }; // patch opcode
	
	// target opcode is fourth memory point 
	if (list.size() == 4) {
		DWORD oldProtect = 0;
		VirtualProtectEx(hProcess, list.back(), sizeof(code), PAGE_EXECUTE_READWRITE, &oldProtect);
		WriteProcessMemory(hProcess, list.back(), code, sizeof(code), NULL);
		VirtualProtectEx(hProcess, list.back(), sizeof(code), oldProtect, NULL);
	
		printf("[*] success\n");
	}
	else {
		printf("[*] fail\n");
	}
}
