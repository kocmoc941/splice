#include <iostream>
#include <Windows.h>

int main(int argc, char **argv)
{
    HANDLE file = CreateFile(__TEXT("test"), GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    DWORD wr;

    WriteFile(file, "yea", 4, &wr, nullptr);
    CloseHandle(file);
    puts("press any key for exit");
    getchar();
    return 0;
}
