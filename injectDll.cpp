#include <Windows.h>
#include <stdio.h>

#define MAX_FILE_PATH 512

typedef HMODULE(WINAPI *PLOADLIBRARYW) (LPCWSTR lpLibFileName);

typedef struct {
	PLOADLIBRARYW lpLoadLibraryW;
	WCHAR lpLibFileName[MAX_FILE_PATH];
} PARAM, *PPARAM;

int InjectFunction(PPARAM param) {
	(param->lpLoadLibraryW)(param->lpLibFileName);
	return 0;
}

int EndOfFunction() { return 0; }

int main(int argc, char *argv[]) {
	WCHAR *target = L"target.exe";
	WCHAR *lib = L"lib.dll";
	
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	CreateProcessW(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	HMODULE hKernel32 = LoadLibraryW(L"kernel32.dll");

	PARAM param;
	wcscpy(param.lpLibFileName, lib);
	param.lpLoadLibraryW = (PLOADLIBRARYW)GetProcAddress(hKernel32, "LoadLibraryW");

	DWORD64 dwFunctionSize = (DWORD64)EndOfFunction - (DWORD64)InjectFunction;

	LPVOID lpFunction = VirtualAllocEx(pi.hProcess, NULL, dwFunctionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID lpParam = VirtualAllocEx(pi.hProcess, NULL, sizeof(param), MEM_COMMIT, PAGE_READWRITE);

	SIZE_T written;
	WriteProcessMemory(pi.hProcess, lpParam, &param, sizeof(param), &written);
	WriteProcessMemory(pi.hProcess, lpFunction, InjectFunction, dwFunctionSize, &written);

	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpFunction, lpParam, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	ResumeThread(pi.hThread);

	VirtualFreeEx(pi.hProcess, lpFunction, dwFunctionSize, MEM_RELEASE);
	VirtualFreeEx(pi.hProcess, lpParam, sizeof(param), MEM_RELEASE);

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
}
