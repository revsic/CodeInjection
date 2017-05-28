# Code Injection

Inject code with certain technique written in cpp.

- DLL Injection : [InjectDll.cpp](https://github.com/revsic/Code-Injection/blob/master/InjectDll.cpp)
- Memory Scanning : [MemoryScanInjector.cpp](https://github.com/revsic/Code-Injection/blob/master/MemoryScanInjector.cpp)
- DLL Injection with User APC : [QueueUserAPC.cpp](https://github.com/revsic/Code-Injection/blob/master/QueueUserAPC.cpp)

## DLL Injection

Inject dll with `CreateRemoteThread` and `LoadLibrary`.

```cpp
VirtualAllocEx(pi.hProcess, NULL, dwLength, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(pi.hProcess, lpLibName, DLL_NAME, dwLength, &written);

HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, NULL, pLoadLibraryW, lpLibName, NULL, NULL);
WaitForSingleObject(hThread, INFINITE);
```

## Memory Scanning

Scan certain instructions and overwrite it.

`ScanMemory` inspects the executable area in memory, finds data coming in as a pattern argument and stores the address in the list.

```cpp
std::vector<LPVOID> list;
BYTE pattern[] = { 0x48, 0x63, 0x4D, 0xC8, 0x89, 0x08, 0x49, 0x63, 0x47, 0x50 }; //target opcode
ScanMemory(hProcess, pattern, sizeof(pattern), list);

BYTE code[] = { 0xC7, 0x00, 0x04, 0x00, 0x00, 0x00 }; // patch opcode
WriteProcessMemory(hProcess, list.back(), code, sizeof(code), NULL);
```

## Queue User APC

[QueueUserAPC](https://msdn.microsoft.com/ko-kr/library/windows/desktop/ms684954) adds user-mode Asynchronous Procedure Call (APC).

Many anti-debugging agents watch CreateRemoteThread is called. In order to bypass this scenario, we can use APC to inject dll.

```cpp
for (auto dwTid : tids) {
	HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, dwTid);
	if (hThread) {
		QueueUserAPC(pLoadLibrary, hThread, (ULONG_PTR)lpAddress);
		CloseHandle(hThread);
	}
}
```
