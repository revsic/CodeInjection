#include <iostream>
#include <string.h>
#include <Windows.h>

typedef struct Param {
	FARPROC loadLibrary;
	char dllName[1024];
} PARAM;

typedef HMODULE(__stdcall *PLOADLIBRARYA) (
	LPCSTR lpLibFileName
);

void InjectFunction(LPVOID lpParam) {
	PARAM* param = (PARAM *)lpParam;
	HMODULE hmd = ((PLOADLIBRARYA)param->loadLibrary)(param->dllName);
}

int main() {
	SIZE_T written;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	int dataSize = -1;
	unsigned char* data = (unsigned char *)InjectFunction;
	while (data[++dataSize] != 0xc3); // opcode ret : 0xC3

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);

	CreateProcess(L"C:\\WINDOWS\\System32\\notepad.exe", NULL, NULL, NULL, false, NULL, NULL, NULL, &si, &pi);
	HANDLE hProcess = pi.hProcess;

	PARAM param;
	HMODULE hMod = LoadLibraryA("Kernel32.dll");
	param.loadLibrary = GetProcAddress(hMod, "LoadLibraryA");
	strcpy(param.dllName, "dllInject.dll");

	LPVOID vAddr = VirtualAllocEx(hProcess, NULL, dataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID argAddr = VirtualAllocEx(hProcess, NULL, sizeof(PARAM), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(hProcess, vAddr, data, dataSize + 1, &written);
	WriteProcessMemory(hProcess, argAddr, (unsigned char *)&param, sizeof(param), &written);

	CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)vAddr, argAddr, 0, NULL);
	std::cout << "[*] create Thread " << std::endl;

	return 0;
}
