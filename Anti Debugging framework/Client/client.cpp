#include <iostream>
#include <string>
#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <Psapi.h>
#include <vector>
#include <sstream>

using namespace std;

bool IsDebugged()
{
    __asm {
        mov eax, dword ptr fs : [0x30]
        mov al, byte ptr[eax + 0x02]
    }
}

BOOL IsLauncher() {
    DWORD cPid = GetCurrentProcessId();
    DWORD pPid = 0;
    PROCESSENTRY32 pe32;
    HANDLE hPProcess;

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        printf("GetLastError : %d", GetLastError());
        CloseHandle(hProcessSnap);
        return false;
    }

    do
    {
        if (cPid == pe32.th32ProcessID) {
            pPid = pe32.th32ParentProcessID;
            break;
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    if (pPid == 0) {
        printf("Client : parent process doesn't exist");
        ExitProcess(1);
    }

    hPProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pPid);
    if (hPProcess == NULL) {
        printf("GetLastError : %d", GetLastError());
    }
    char buffer[MAX_PATH];
    GetProcessImageFileNameA(hPProcess, buffer, MAX_PATH);
    string pName = string(buffer);
    CloseHandle(hPProcess);
    
    //printf("Parent Name : %s\n", pName.substr(pName.find("Launcher.exe")));
    vector<string> pNameVec;
    string temp;
    istringstream ss(pName);
    while (getline(ss, temp, '\\')) {
        pNameVec.push_back(temp);
    }
    pName = pNameVec.back();
    //printf("Parent Name : %s\n", pName);
    if (pName != "Launcher.exe") {
        printf("Client : Parent process is not Launcher.exe. 프로그램 종료\n");
        ExitProcess(1);
    }
    else {
        printf("Client : 부모 프로세스 확인 완료\n");
    }

    return true;
}

void Echo()
{
    string input;
    int i = 0;

    printf("Client : echo 실행. \"exit\" 입력 시 종료\n");

    while (true) {
        cout << ">>>";
        getline(cin, input);

        if (input == "exit") {
            cout << "Client : 프로그램 종료" << endl;
            break;
        }
        cout << "echo : " << input << endl;

    }
}

int main()
{
    if (!IsDebugged()) {
        printf("Launcher가 디버거로 붙은 상태에서만 실행하기\n");
        ExitProcess(1);
    }

    IsLauncher();

    Echo();

    return 0;
}
