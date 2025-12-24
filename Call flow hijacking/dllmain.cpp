// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
char buf[4096];

BOOL WINAPI FakeWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

    sprintf_s(buf, "FakeWriteRile() Hit: nNumberOfBytesToWrite=%u\n", nNumberOfBytesToWrite);
    OutputDebugStringA(buf);
  
    const char* str = "Compromised";
    BOOL bRetVal = WriteFile(hFile, str, strlen(str), lpNumberOfBytesWritten, lpOverlapped);
    *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
    return bRetVal;
}

void PatchIAT(LPDWORD lpAddress, DWORD data) {
    DWORD flOldProtect, flOldProtect2;
    VirtualProtect((LPVOID)lpAddress, sizeof(DWORD), PAGE_READWRITE, &flOldProtect);
    *lpAddress = data;
    VirtualProtect((LPVOID)lpAddress, sizeof(DWORD), flOldProtect, &flOldProtect2);
}

BOOL hack() {
    // WirteFile RVA 하드코딩
    // Notepad++
    LPDWORD lpTarget = (LPDWORD)((char*)GetModuleHandleA(NULL) + 0x3E621C);
    // TextPad
    //LPDWORD lpTarget = (LPDWORD)((char*)GetModuleHandleA(NULL) + 0x4335C8);
    PatchIAT((LPDWORD)lpTarget, (DWORD)FakeWriteFile);

    return TRUE;
}
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        return hack();

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

