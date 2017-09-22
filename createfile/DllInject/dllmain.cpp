// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>
#include <stdint.h>
#include <iostream>

#pragma pack(push, one, 1)
struct jmpRamp
{
    u_char jmp;
    uint32_t offset;
} originalRamp;
#pragma pack(pop, one)

void printMessage(std::wstring str)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out == INVALID_HANDLE_VALUE) {
        printMessage(L"GetStdHandle error");
        return;
    }
    DWORD wr;
    str += L"\n";
    WriteConsole(out, str.c_str(), str.length(), &wr, nullptr);
}

const uint32_t calculateAddr(void *lpCode, void *lpTargetAddress)
{
    const auto codeAddress = (uint32_t)lpCode + 5;
    const auto targetAddress = (uint32_t)lpTargetAddress;
    if (codeAddress > targetAddress) {
        wchar_t buf[128];
        wsprintf(buf, __TEXT("codeAddress > targetAddress\ncodeAddress = %X targetAddress = %X\n"
            "targetAddress - codeAddress = %X"), codeAddress, targetAddress, targetAddress - codeAddress);
        printMessage(buf);
        return targetAddress - codeAddress;
    }
    if (codeAddress < targetAddress) {
        wchar_t buf[128];
        wsprintf(buf, __TEXT("codeAddress < targetAddress\ncodeAddress = %X targetAddress = %X\n"
            "targetAddress - codeAddress = %X"), codeAddress, targetAddress, targetAddress - codeAddress);
        printMessage(buf);
        return codeAddress - targetAddress;
    }
    return 0;
}

HANDLE WINAPI MyCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    MessageBoxA(nullptr, "fake create file", "fuck", MB_OK);
    return nullptr;
}

jmpRamp *code;

DWORD inject()
{
    HANDLE(*OriginCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    HMODULE dll = GetModuleHandle(L"kernel32.dll");
    if (dll == INVALID_HANDLE_VALUE) {
        printMessage(L"GetModuleHandle error get kernel32.dll address");
        return EXIT_FAILURE;
    }

    OriginCreateFileW = (HANDLE(*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))GetProcAddress(dll, "CreateFileW");

    if (OriginCreateFileW != nullptr) {
        printMessage(L"OriginCreateFileW get address success");
    } else {
        printMessage(L"OriginCreateFileW get address error");
        return EXIT_FAILURE;
    }

    code = (jmpRamp *)OriginCreateFileW;
    originalRamp = *code;
    DWORD old;
    VirtualProtect(code, sizeof(jmpRamp), PAGE_EXECUTE_READWRITE, &old);
    code->jmp = 0xE9;
    code->offset = calculateAddr(code, &MyCreateFileW);
    VirtualProtect(code, sizeof(jmpRamp), old, &old);
    wchar_t mess[128];
    wsprintf(mess, L"hook setted, replaced %X on %X, press return for continue", (DWORD)OriginCreateFileW, (DWORD)MyCreateFileW);
    printMessage(mess);

    return EXIT_SUCCESS;
}

DWORD restoreInject()
{
    DWORD old;
    VirtualProtect(code, sizeof(jmpRamp), PAGE_EXECUTE_READWRITE, &old);
    *code = originalRamp;
    VirtualProtect(code, sizeof(jmpRamp), old, &old);
    return EXIT_SUCCESS;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
    case DLL_PROCESS_ATTACH:
        printMessage(L"DLL_PROCESS_ATTACH");
        inject();
        break;
	case DLL_THREAD_ATTACH:
        printMessage(L"DLL_THREAD_ATTACH");
        break;
	case DLL_THREAD_DETACH:
        printMessage(L"DLL_THREAD_DETACH");
        break;
	case DLL_PROCESS_DETACH:
        printMessage(L"DLL_PROCESS_DETACH");
        restoreInject();
		break;
	}
	return TRUE;
}

