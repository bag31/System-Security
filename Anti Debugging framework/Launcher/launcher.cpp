#include <windows.h>
#include <stdio.h>

// 디버거 감지 함수
#pragma comment(linker, "/INCLUDE:__tls_used")  // 프로젝트(링커) 설정. tsl 사용
#pragma comment(linker, "/INCLUDE:_pCallBacks") // pCallBacks 변수를 링커에 전달

int is_running = 1;
HANDLE hThread = NULL;

__inline BOOL CheckDebugger() {
    __asm {
        mov eax, dword ptr fs : [0x30]
        movzx eax, byte ptr ds : [eax + 0x02]
    }
}

DWORD WINAPI debugger_watchdog(void* arg) {
    while (is_running) {
        if (CheckDebugger()) {
            printf("Launcher : 디버거 감지. 프로그램을 종료\n");
            Sleep(10000);
            ExitProcess(1);
        }
        else {
            Sleep(100);
        }
    }
}

void NTAPI TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    switch (Reason) {
    case 1:
        if (CheckDebugger()) {
            printf("Launcher : 디버거 감지. 프로그램 종료 (TLS 콜백)\n");
            Sleep(10000);
            ExitProcess(1);
        }
        else {
            hThread = CreateThread(NULL, 0, debugger_watchdog, 0, 0, 0);
        }
        break;
    }
}

#pragma data_seg(".CRT$XLX")
extern "C" PIMAGE_TLS_CALLBACK pCallBacks[] = { TLS_CALLBACK, 0 };
#pragma data_seg()

// Client 관련
int ClientDebugger()
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    const char* clientPath = "Client.exe"; // 같은 폴더에 존재

    printf("Launcher : Client 실행 중...\n");

    if (!CreateProcessA(
        clientPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_ONLY_THIS_PROCESS,
        NULL,
        NULL,
        &si,
        &pi))
    {
        DWORD err = GetLastError();
        printf("Launcher : Client.exe 실행 실패. GetLastError() = %lu\n", err);
        return 1;
    }

    printf("Launcher : Client.exe 실행 및 디버깅 시작\n");

    DEBUG_EVENT DebugEv;
    BOOL debugging = TRUE;

    // 디버깅 루프
    while (debugging) {
        // 디버그 이벤트
        WaitForDebugEvent(&DebugEv, INFINITE);
        
        switch (DebugEv.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (DebugEv.u.CreateProcessInfo.hFile) {
                CloseHandle(DebugEv.u.CreateProcessInfo.hFile);
            }
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            printf("Launcher : Client 프로세스 종료\n");
            debugging = FALSE;
            break;

        default:
            // 나머지 이벤트
            break;
        }
        ContinueDebugEvent(
            DebugEv.dwProcessId,
            DebugEv.dwThreadId,
            DBG_CONTINUE
        );
    }

    // 핸들 정리
    if (pi.hThread)
        CloseHandle(pi.hThread);
    if (pi.hProcess)
        CloseHandle(pi.hProcess);

    printf("Launcher : 디버깅 루프 종료\n");
    return 0;
}

int main()
{
    printf("Launcher : 프로그램 시작\n");

    int result = ClientDebugger();

    // 디버거 감지 스레드 종료
    is_running = 0;
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        hThread = NULL;
    }

    printf("Launcher : 프로그램 종료");
    Sleep(10000);
    return 0;
}


