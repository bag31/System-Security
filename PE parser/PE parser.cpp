#include <Windows.h>
#include <stdio.h>

int main(void)
{
    /* 본인 가상머신에 탑재된 x86 PE 파일의 경로로 하드코딩*/
    //char path_pefile[] = "..\\abex_crackme1.exe";
    //char path_pefile[] = "..\\npp.8.8.6.Installer.exe";
    char path_pefile[] = "..\\Release\\Main.exe";

    HANDLE hFile = NULL, hFileMap = NULL; /*Win32 API 호출 과정에서 사용되는 변수*/
    LPBYTE lpFileBase = NULL; /*메모리에 매핑된 파일 컨텐츠의 위치*/
    DWORD dwSize = 0; /*PE 파일 사이즈*/

    PIMAGE_DOS_HEADER pDosHeader = NULL; /*DOS 헤더 구조체의 포인터*/
    PIMAGE_NT_HEADERS pNtHeader = NULL; /*NT 헤더 구조체의 포인터*/

    hFile = CreateFileA(path_pefile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFileA() failed. Error code=%lu\n", GetLastError());
        return GetLastError();
    }
    dwSize = GetFileSize(hFile, 0);
    printf("File size=%lu bytes\n\n", dwSize);


    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    // lpFileBase 포인터는 OS에 의해 메모리에 로드된 PE 파일의 가장 첫 바이트를 가리킴.
    //lpFileBase가 NULL이라면 MapViewOfFile() 함수가 실패했다는 의미이다. 여기서는 예외 처리를 생략
    lpFileBase = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, dwSize);

    printf("File signature=%c%c\n", lpFileBase[0], lpFileBase[1]);

    pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    printf("Offset to the NT header=%#x\n\n", pDosHeader->e_lfanew);

    pNtHeader = (PIMAGE_NT_HEADERS)(lpFileBase + pDosHeader->e_lfanew);
    printf("OptionalHeader.BaseOfCode=%#x\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("OptionalHeader.SizeOfCode=%#x\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("OptionalHeader.AddressOfEntryPoint=%#x\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("OptionalHeader.BaseOfData=%#x\n", pNtHeader->OptionalHeader.BaseOfData);
    printf("OptionalHeader.ImageBase=%#x\n\n", pNtHeader->OptionalHeader.ImageBase);

    printf("### SECTION INFORMATION ###\n");

    // --- SECTION INFORMATION ---
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNtHeader);
    WORD nSec = pNtHeader->FileHeader.NumberOfSections;

    for (WORD i = 0; i < nSec; ++i) {
        char name[9] = { 0 };
        memcpy(name, pSec[i].Name, 8);
        printf("%d번째 section: %s\n", i + 1, name);
        printf("PointerToRawData: %#x\n", pSec[i].PointerToRawData);
        printf("SizeOfRawData: %#x\n", pSec[i].SizeOfRawData);
        printf("VirtualAddress: %#x\n", pSec[i].VirtualAddress);
        printf("VirtualSize: %#x\n\n", pSec[i].Misc.VirtualSize);
    }

    // --- 헬퍼: RVA -> 파일 포인터 / RAW ---
    auto RvaToPtr = [&](DWORD rva) -> LPBYTE {
        for (WORD i = 0; i < nSec; ++i) {
            DWORD va = pSec[i].VirtualAddress;
            DWORD vsize = pSec[i].Misc.VirtualSize;
            DWORD rsize = pSec[i].SizeOfRawData;
            DWORD span = (vsize > rsize) ? vsize : rsize; // 경계 안전
            if (rva >= va && rva < va + span) {
                DWORD raw = pSec[i].PointerToRawData + (rva - va);
                return lpFileBase + raw;
            }
        }
        // 헤더 영역(RVA가 첫 섹션 시작보다 작음)
        if (nSec && rva < pSec[0].VirtualAddress) return lpFileBase + rva;
        return (LPBYTE)NULL;
        };
    auto RvaToRaw = [&](DWORD rva) -> DWORD {
        for (WORD i = 0; i < nSec; ++i) {
            DWORD va = pSec[i].VirtualAddress;
            DWORD vsize = pSec[i].Misc.VirtualSize;
            DWORD rsize = pSec[i].SizeOfRawData;
            DWORD span = (vsize > rsize) ? vsize : rsize;
            if (rva >= va && rva < va + span) {
                return pSec[i].PointerToRawData + (rva - va);
            }
        }
        if (nSec && rva < pSec[0].VirtualAddress) return rva; // 헤더
        return 0;
        };

    // --- IAT ---
    printf("### IAT ###\n");
    IMAGE_DATA_DIRECTORY impDir =
        pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (impDir.VirtualAddress == 0) {
        // 예시에는 IAT가 존재하지만, 없을 때도 깔끔히 처리
        printf("IAT가 저장된 섹션: (없음)\n");
    }
    else {
        // IAT가 저장된 섹션 이름 찾기
        const char* iatSecName = "(unknown)";
        char nameBuf[9] = { 0 };
        for (WORD i = 0; i < nSec; ++i) {
            DWORD va = pSec[i].VirtualAddress;
            DWORD vsize = pSec[i].Misc.VirtualSize;
            DWORD rsize = pSec[i].SizeOfRawData;
            DWORD span = (vsize > rsize) ? vsize : rsize;
            if (impDir.VirtualAddress >= va && impDir.VirtualAddress < va + span) {
                memset(nameBuf, 0, sizeof(nameBuf));
                memcpy(nameBuf, pSec[i].Name, 8);
                iatSecName = nameBuf;
                break;
            }
        }

        DWORD rawOfIat = RvaToRaw(impDir.VirtualAddress);
        printf("IAT가 저장된 섹션: %s\n", iatSecName);
        printf("RVA to RAW: %#x->%#x\n", impDir.VirtualAddress, rawOfIat);

        // Import Descriptor 배열 시작
        PIMAGE_IMPORT_DESCRIPTOR pImp =
            (PIMAGE_IMPORT_DESCRIPTOR)RvaToPtr(impDir.VirtualAddress);

        if (pImp) {
            for (int d = 0; pImp[d].Name != 0; ++d) {
                char* dllName = (char*)RvaToPtr(pImp[d].Name);
                if (!dllName) dllName = (char*)"(null)";
                printf("ImportDescriptor[%d].Name=%s\n", d, dllName);

                // 이름 테이블. 없으면 FirstThunk 사용
                DWORD oftRva = pImp[d].OriginalFirstThunk
                    ? pImp[d].OriginalFirstThunk
                    : pImp[d].FirstThunk;

                PIMAGE_THUNK_DATA32 pThunk =
                    (PIMAGE_THUNK_DATA32)RvaToPtr(oftRva);
                if (!pThunk) continue;

                for (int i = 0; pThunk[i].u1.AddressOfData != 0; ++i) {
                    DWORD u = pThunk[i].u1.AddressOfData;

                    // ordinal import는 예시에 없으므로 이름 import만 예시 형식으로 출력
                    if (u & IMAGE_ORDINAL_FLAG32) {
                        WORD ord = (WORD)(u & 0xFFFF);
                        printf("- function name (RVA=%#x), [ordinal %u]\n", u, ord);
                    }
                    else {
                        PIMAGE_IMPORT_BY_NAME pByName =
                            (PIMAGE_IMPORT_BY_NAME)RvaToPtr(u);
                        if (!pByName) continue;
                        printf("- function name (RVA=%#x), %s\n",
                            u, (const char*)pByName->Name);
                    }
                }
            }
        }
    }


    /*Windows로부터 할당받은 리소스를 역순으로 반환*/
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMap);
    CloseHandle(hFile);
    /*main() 함수가 끝까지 실행되었음을 알리기 위해 0을 반환*/
    return 0;
}
