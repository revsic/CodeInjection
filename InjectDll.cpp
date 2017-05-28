#include <Windows.h>

#define PROC_NAME L""
#define DLL_NAME L""

int main() {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));

    CreateProcessW(PROC_NAME, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW =
    	(LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    SIZE_T dwLength = (wcslen(DLL_NAME) + 1) * 2;
    LPVOID lpLibName = VirtualAllocEx(pi.hProcess, NULL, dwLength, MEM_COMMIT, PAGE_READWRITE);

    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, lpLibName, DLL_NAME, dwLength, &written);

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, NULL, pLoadLibraryW, lpLibName, NULL, NULL);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    ResumeThread(pi.hThread);

    VirtualFreeEx(pi.hProcess, lpLibName, dwLength, MEM_RELEASE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
