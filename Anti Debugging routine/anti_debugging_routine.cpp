#include <stdio.h>
#include <Windows.h>

// TLS callback 구현
#pragma comment(linker, "/INCLUDE:__tls_used") // 프로젝트(링커)설정. tsl 사용
#pragma comment(linker, "/INCLUDE:_pCallBacks") // pCallBacks 변수를 링커에 전달

// reason을 건드려서 무한 루프 안 돌게 해야 하도록 함
int is_running = 1;
HANDLE hThread = NULL;

int ImportantFunction();
__inline BOOL CheckDebugger() {
	__asm {
		mov eax, dword ptr fs : [0x30]
		movzx eax, byte ptr ds : [eax + 0x02]
	}
}

DWORD WINAPI debugger_watchdog(void* arg) {
	DWORD watch_count = 0;
	while (is_running) {
		if (CheckDebugger()) {
			printf("디버거 발견\n");
			ExitProcess(1);
		}
		else Sleep(100);
	}
}
void NTAPI TLS_CALLBACK1(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
	switch (Reason) {
	case 1:
		if (CheckDebugger()) {
			printf("디버거 발견\n");
			ExitProcess(1);
		}
		else {
			printf("TLS CALLBACK 1 WITH Reason=%u\n", Reason);
			hThread = CreateThread(0, 0, debugger_watchdog, 0, 0, 0);
		}
		break;
	}

}

#pragma data_seg(".CRT$XLX")
extern "C" PIMAGE_TLS_CALLBACK pCallBacks[] = { TLS_CALLBACK1, 0 };

#pragma data_seg()

// 임시 중요 함수
int ImportantFunction() {
	int num = 1;
	while (true) {

		printf("number %d\n", num);
		Sleep(1000);
		num += 1;

	}
}

int main() {
	printf("프로그램 시작\n");

	ImportantFunction();

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	hThread = NULL;
	printf("프로그램 종료\n");
	return 0;
}
