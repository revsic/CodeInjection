#include <iostream>
#include <iomanip>
#include <string.h>
#include <Windows.h>
#include <tlhelp32.h>

using namespace std;

typedef struct Param {
	FARPROC createFunc;
	FARPROC writeFunc;
	FARPROC closeFunc;
	char data[1024];
	char fileName[1024];
} PARAM;

typedef HANDLE (__stdcall *PCREATEFILE) (
	LPCTSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
);

typedef BOOL (__stdcall *PWRITEFILE) (
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
);

typedef BOOL (__stdcall *PCLOSEHANDLE) (
	HANDLE hObject
);

void InjectFunction(LPVOID lpParam) {
	PARAM* param = (PARAM *)lpParam;
	DWORD written;
	int len = strlen(param->data) + 1;

	HANDLE hFile = ((PCREATEFILE)(param->createFunc))((LPCTSTR)param->fileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		hFile = ((PCREATEFILE)(param->createFunc))((LPCTSTR)param->fileName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	}

	((PWRITEFILE)(param->writeFunc))(hFile, param->data, len, &written, NULL);
	((PCLOSEHANDLE)(param->closeFunc))(hFile);
}

int main() {
	SIZE_T written;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	int dataSize = -1;
	unsigned char* data = (unsigned char *)InjectFunction;
	while (data[++dataSize] != 0xc3);

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);

	CreateProcess(L"C:\\WINDOWS\\System32\\notepad.exe", NULL, NULL, NULL, false, NULL, NULL, NULL, &si, &pi);
	HANDLE hProcess = pi.hProcess;

	PARAM param;
	HMODULE hMod = LoadLibraryA("Kernel32.dll");
	param.createFunc = GetProcAddress(hMod, "CreateFileA");
	param.writeFunc = GetProcAddress(hMod, "WriteFile");
	param.closeFunc = GetProcAddress(hMod, "CloseHandle");

	strcpy(param.data, "Hello !! I'm revsic ~");
	char *tmp = getenv("USERPROFILE");
	if (tmp != NULL) {
		snprintf(param.fileName, sizeof(param.fileName), "%s\\Desktop\\inject2.txt", getenv("USERPROFILE"));
	}
	else {
		strcpy(param.fileName, "inject2.txt");
	}
	

	LPVOID vAddr = VirtualAllocEx(hProcess, NULL, dataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID argAddr = VirtualAllocEx(hProcess, NULL, sizeof(PARAM), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	cout << "[*] vaddr : " << hex << vAddr << endl;
	cout << "[*] argAddr : " << hex << argAddr << endl;

	WriteProcessMemory(hProcess, vAddr, data, dataSize + 1, &written);
	WriteProcessMemory(hProcess, argAddr, (unsigned char *)&param, sizeof(param), &written);

	CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)vAddr, argAddr, 0, NULL);
	cout << "[*] create Thread " << endl << endl;

	return 0;
}