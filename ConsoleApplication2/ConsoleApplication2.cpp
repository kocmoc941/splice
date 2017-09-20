// ConsoleApplication2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <iostream>

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

int main(int argc, char **argv) 
{
    const DWORD id = findProcessByName(L"explorer");

    if (!setTokenPrivileges(id))
        printMessage(L"setTokenPrivileges error");
    else
        printMessage(L"setTokenPrivileges success");

    return 0;
}

