// 명시적 링킹을 통해 IAT에 MessageBoxA() 함수를 기재하지 않고 함수 사용 가능
#include <windows.h>
#include <stdio.h>

// 함수 포인터 사전 정의
typedef int (WINAPI* MessageBoxAPointer)(HWND, LPCSTR, LPCSTR, UINT);

int main()
{
    // user32.dll를 LoadLibrary로 호출
    HMODULE user32 = LoadLibrary(TEXT("user32.dll"));

    // MessageBoxA 함수 이름을 이용하여 함수 주소를 포인터에 저장
    MessageBoxAPointer MessageBoxA = (MessageBoxAPointer)GetProcAddress(user32, "MessageBoxA");

    // 함수 포인터를 통해 MessageBoxA 호출
    MessageBoxA(
        NULL,
        "abcdefg",
        "알파벳",
        MB_OK
    );

    // 함수 사용 후 로드한 dll 해제
    FreeLibrary(user32);
    return 0;
}
