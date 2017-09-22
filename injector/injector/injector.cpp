#include <Windows.h>
#include <TlHelp32.h>

#include <iostream>
#include <fstream>

void printMessage(std::wstring str)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out == INVALID_HANDLE_VALUE)
        return;
    DWORD wr;
    str += L"\n";
    WriteConsole(out, str.c_str(), str.length(), &wr, nullptr);
}

bool setTokenPrivileges(const DWORD pid)
{
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    HANDLE token;

    if (!OpenProcessToken(pHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        printMessage(L"OpenProcessToken error");
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        printMessage(L"LookupPrivilegeValue error");
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, false, &tp, sizeof(tp), nullptr, nullptr)) {
        printMessage(L"AdjustTokenPrivileges error");
        return false;
    }

    return true;
}

void printModuleList(const DWORD pid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    Module32First(snapshot, &me);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);

    do {
        wchar_t szBuff[512];
        wsprintf(szBuff, L"  ba: %08X, bs: %08X, %s\r\n",
            me.modBaseAddr, 
            me.modBaseSize,
            me.szModule);
        DWORD dwTemp;
        WriteConsole(out, szBuff, lstrlen(szBuff), &dwTemp, NULL);
    } while (Module32Next(snapshot, &me));
}

const DWORD findProcessByName(const std::wstring &name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    Process32First(snapshot, &pe);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);

    do {
        if (!wcsstr(pe.szExeFile, name.c_str()))
            continue;
        wchar_t szBuff[512];
        wsprintf(szBuff, L"=== %08X %s ===\r\n", pe.th32ProcessID, pe.szExeFile);
        DWORD dwTemp;
        WriteConsole(out, szBuff, lstrlen(szBuff), &dwTemp, NULL);
        printModuleList(pe.th32ProcessID);
        return pe.th32ProcessID;
    } while (Process32Next(snapshot, &pe));

    return 0;
}

HANDLE
WINAPI
MyCreateFileW(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
)
{
    MessageBoxA(nullptr, "fake create file", "fuck", MB_OK);
    return nullptr;
}

#pragma pack(push, one, 1)
struct jmpRamp
{
    u_char jmp;
    uint32_t offset;
};
#pragma pack(pop, one)

uint32_t calculateAddr(void *a, void *b)
{
    uint32_t _a = (uint32_t)a;
    uint32_t _b = (uint32_t)b;
    if (_a < _b) {
        printMessage(L"_a < _b");
        return _b - _a - 5;
    }
    if (_a > _b) {
        printMessage(L"_a > _b");
        return _a - _b - 5;
    }
    return 0;
}

DWORD inject()
{
    HANDLE (*OriginCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    HMODULE dll = GetModuleHandle(L"kernel32.dll");
    if (dll == INVALID_HANDLE_VALUE) {
        printMessage(L"GetModuleHandle error get kernel32.dll address");
        return EXIT_FAILURE;
    }

    OriginCreateFileW = (HANDLE (*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD,
            HANDLE))GetProcAddress(dll, "CreateFileW");

    if (OriginCreateFileW != nullptr) {
        printMessage(L"OriginCreateFileW get address success");
    } else {
        printMessage(L"OriginCreateFileW get address error");
        return EXIT_FAILURE;
    }

    jmpRamp *code;
    code = (jmpRamp *)OriginCreateFileW;
    DWORD old;
    VirtualProtect(code, sizeof(jmpRamp), PAGE_EXECUTE_READWRITE, &old);
    code->jmp = 0xE9;
    code->offset = calculateAddr(MyCreateFileW, OriginCreateFileW);
    VirtualProtect(code, sizeof(jmpRamp), old, &old);

    return EXIT_SUCCESS;
}

void execThisToForeignModule(const DWORD pid)
{
    HMODULE hModule = GetModuleHandle(nullptr);
    DWORD size = ((PIMAGE_OPTIONAL_HEADER)((LPVOID)((BYTE *)(hModule) + ((PIMAGE_DOS_HEADER)(hModule))->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))))->SizeOfImage;
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (process == INVALID_HANDLE_VALUE) {
        printMessage(L"OpenProcess error");
        return;
    }
    LPVOID alloc = (char *)VirtualAllocEx(process, hModule, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (process == nullptr) {
        printMessage(L"VirtualAllocEx return null address");
        return;
    }

    DWORD ByteOfWritten;
    BOOL w = WriteProcessMemory(process, alloc, hModule, size, &ByteOfWritten);
    if (w == false) {
        printMessage(L"WriteProcessMemory failure");
        return;
    }

    DWORD id;
    HANDLE thread = CreateRemoteThread(process, 0, 0, (LPTHREAD_START_ROUTINE)inject, (LPVOID)alloc, 0, &id);
    if (thread == nullptr) {
        printMessage(L"CreateRemoteThread error");
        return;
    }

    printMessage(L"CreateRemoteThread success");
    printMessage(L"waiting process");
    WaitForSingleObject(process, INFINITE);
    VirtualFree(alloc, size, MEM_RELEASE);
    CloseHandle(process);
}

void execDllToForeignModule(const DWORD pid, const std::string dllPath)
{
    std::ifstream dll(dllPath, std::ios_base::in);
    if (!dll.is_open()) {
        printMessage(L"invalid dll name or path");
        return;
    }
    dll.close();

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (process == INVALID_HANDLE_VALUE) {
        printMessage(L"OpenProcess error");
        return;
    }
    DWORD size = dllPath.length();
    LPVOID alloc = (char *)VirtualAllocEx(process, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (process == nullptr) {
        printMessage(L"VirtualAllocEx return null address");
        return;
    }

    DWORD byteOfWritten;
    BOOL w = WriteProcessMemory(process, alloc, dllPath.c_str(), size, &byteOfWritten);
    if (w == false) {
        printMessage(L"WriteProcessMemory failure");
        return;
    } else {
        wchar_t mess[128];
        wsprintf(mess, L"Written %u bytes", byteOfWritten);
        printMessage(mess);
    }

    HMODULE module = GetModuleHandle(L"kernel32.dll");
    if (module == INVALID_HANDLE_VALUE) {
        printMessage(L"GetModuleHandle error get kernel32.dll address");
        return;
    }
    typedef HMODULE (* OriginalLoadLibraryA)(LPCTSTR lpFileName);
    OriginalLoadLibraryA loadLib;
    loadLib = (OriginalLoadLibraryA)GetProcAddress(module, "LoadLibraryA");
    if (loadLib == nullptr) {
        printMessage(L"GetProcAddress error get LoadLibraryA address");
        return;
    }
    DWORD id;
    HANDLE thread = CreateRemoteThread(process, 0, 0, (LPTHREAD_START_ROUTINE)loadLib, (LPVOID)alloc, 0, &id);
    if (thread == nullptr) {
        printMessage(L"CreateRemoteThread error");
        return;
    }

    printMessage(L"CreateRemoteThread success");

    printMessage(L"Waiting inject");
    if (WaitForSingleObject(process, 1000) == WAIT_FAILED)
        printMessage(L"WaitForSingleObject error");

    if (!VirtualFreeEx(process, alloc, 0, MEM_RELEASE)) {
        printMessage(L"VirtualFreeEx error");
        DWORD errorMessageID = ::GetLastError();
        if (errorMessageID == 0)
            return;

        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errorMessageID, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

        std::string message(messageBuffer, size);
        std::wstring wmessage(message.begin(), message.end());
        printMessage(wmessage);

        LocalFree(messageBuffer);
    }

    if (!CloseHandle(process))
        printMessage(L"CloseHandle error");

    printMessage(L"Inject success");
}

int main(int argc, char **argv) 
{
    const DWORD pid = findProcessByName(L"createfile");

    if (!setTokenPrivileges(pid))
        printMessage(L"setTokenPrivileges error");
    else
        printMessage(L"setTokenPrivileges success");
    //inject();
    //execThisToForeignModule(pid);
    execDllToForeignModule(pid, "DllInject.dll");

    /*puts("press any key for create file");
    std::cin.get();
    std::cin.ignore(std::cin.rdbuf()->in_avail());
    HANDLE file = CreateFile(__TEXT("test"), GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    DWORD wr;

    WriteFile(file, "yea", 4, &wr, nullptr);
    CloseHandle(file);*/

    std::cout << "press any key for exit";
    std::cin.get();
    return 0;
}
