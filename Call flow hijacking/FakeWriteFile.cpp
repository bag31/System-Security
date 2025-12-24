// Main.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.

#include <stdio.h>
#include <Windows.h>
void InjectDLL(DWORD pid, LPCSTR dll);
int main() {
	DWORD pid = NULL;
	const char* path = "..\\DLLInject_FakeWriteFile\\Release\\DLLInject.dll";
	if (GetFileAttributesA(path) == 0xffffffff) {
		printf("DLL not found.\n");
		return 1;
	}
	while (true) {
		printf("Target Process PID: ");
		scanf_s("%d", &pid);
		if (pid == 0) break;
		InjectDLL(pid, path);
	}
	return 0;
}

void InjectDLL(DWORD pid, LPCSTR dll) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (NULL == hProcess)
	{
		printf("Process not found\n");
		return;
	}
	LPVOID lpAddr = VirtualAllocEx(hProcess, NULL, strlen(dll) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (lpAddr)
	{
		WriteProcessMemory(hProcess, lpAddr, dll, strlen(dll) + 1, NULL);
	}
	else
	{
		printf("VirtualAllocEx() failure.\n");
		return;
	}
	LPTHREAD_START_ROUTINE pfnLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	if (pfnLoadLibraryA)
	{
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnLoadLibraryA, lpAddr, 0, NULL);
		DWORD dwExitCode = NULL;
		if (hThread)
		{
			printf("Injection successful!\n");
			WaitForSingleObject(hThread, INFINITE);
			if (GetExitCodeThread(hThread, &dwExitCode))
				printf("Injected DLL ImageBase: %#x\n", dwExitCode);
			CloseHandle(hThread);
		}
		else
		{
			printf("Injection failure.\n");
		}
	}
	VirtualFreeEx(hProcess, lpAddr, 0, MEM_RELEASE); //VirtualAllocEx로 획득한 힙 반환
}
