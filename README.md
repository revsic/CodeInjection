# Code Injection

Inject code with certain technique written in cpp.

- DLL Injection : [injectDll.cpp](https://github.com/revsic/Code-Injection/blob/master/injectDll.cpp)
- Memory Scanning : [MemoryScanInjector.cpp](https://github.com/revsic/Code-Injection/blob/master/MemoryScanInjector.cpp)

## DLL Injection

Inject dll with `CreateRemoteThread` and `LoadLibrary`.

```cpp
// inject function
int InjectFunction(PPARAM param) {
	(param->lpLoadLibraryW)(param->lpLibFileName);
	return 0;
}

// main
PARAM param;
wcscpy(param.lpLibFileName, lib);
param.lpLoadLibraryW = (PLOADLIBRARYW)GetProcAddress(hKernel32, "LoadLibraryW");

HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpFunction, lpParam, NULL, NULL);
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
