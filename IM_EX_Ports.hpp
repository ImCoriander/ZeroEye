#include <Windows.h>
#include <iostream>
#include <dbghelp.h> // 需要链接 DbgHelp 库
#pragma comment(lib, "dbghelp.lib") // 链接 DbgHelp 库


void SetConsoleColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

//导出表
void ListExportedFunctions(const std::string& filePath, bool flag, std::vector<std::string>& Funclist) {

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return;
    }

    LPVOID pMappedFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMappedFile) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pMappedFile);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(pMappedFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(pMappedFile) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        UnmapViewOfFile(pMappedFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    bool is64Bit = (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    DWORD exportTableRVA;

    if (is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(ntHeaders);
        exportTableRVA = ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }
    else {
        PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(ntHeaders);
        exportTableRVA = ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }
    if (!flag) {
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << filePath << (is64Bit ? ": x64" : ": x86") << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    if (exportTableRVA == 0) {
        UnmapViewOfFile(pMappedFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<BYTE*>(pMappedFile) + exportTableRVA);

    DWORD* nameRVAArray = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(pMappedFile) + exportDirectory->AddressOfNames);
    DWORD* funcAddrArray = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(pMappedFile) + exportDirectory->AddressOfFunctions);
    WORD* ordinalArray = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(pMappedFile) + exportDirectory->AddressOfNameOrdinals);

    char* dllName = reinterpret_cast<char*>(reinterpret_cast<BYTE*>(pMappedFile) + exportDirectory->Name);
    if (!flag) {
        std::cout << "Exported Functions:" << std::endl;
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << dllName << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    int a = 0;
    char undecoratedName[1024]; // 用于存储解码后的符号
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* funcName = reinterpret_cast<char*>(reinterpret_cast<BYTE*>(pMappedFile) + nameRVAArray[i]);
        DWORD funcRVA = funcAddrArray[ordinalArray[i]];

        // 解码修饰符号
        if (UnDecorateSymbolName(funcName, undecoratedName, sizeof(undecoratedName), UNDNAME_COMPLETE)) {
            Funclist.push_back(undecoratedName); // 存储解码后的符号
            if (!flag) {
                std::cout << ++a << "\t"
                    << std::setw(40) << std::left << undecoratedName
                    << "\tRVA: 0x" << std::left << funcRVA
                    << "\tOrdinal: " << std::left << (exportDirectory->Base + ordinalArray[i])
                    << std::endl;
            }
        }
        else {
            Funclist.push_back(funcName); // 如果解码失败，存储原始符号
            if (!flag) {
                std::cout << ++a << "\t"
                    << std::setw(40) << std::left << funcName
                    << "\tRVA: 0x" << std::left << funcRVA
                    << "\tOrdinal: " << std::left << (exportDirectory->Base + ordinalArray[i])
                    << std::endl;
            }
        }
    }

    UnmapViewOfFile(pMappedFile);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return;
}
//导入表
void ListImportedFunctions(const std::string& filePath) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        //std::cerr << "Failed to open file." << std::endl;
        return;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        //std::cerr << "Failed to create file mapping." << std::endl;
        return;
    }

    LPVOID pMappedFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMappedFile) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        //std::cerr << "Failed to map view of file." << std::endl;
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pMappedFile);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(pMappedFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        //std::cerr << "Invalid DOS header signature." << std::endl;
        return;
    }

    PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<BYTE*>(pMappedFile) + dosHeader->e_lfanew);
    if (ntHeaders32->Signature != IMAGE_NT_SIGNATURE) {
        UnmapViewOfFile(pMappedFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        //std::cerr << "Invalid NT header signature." << std::endl;
        return;
    }

    bool is64Bit = (ntHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    DWORD importTableRVA;

    if (is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(ntHeaders32);
        importTableRVA = ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }
    else {
        importTableRVA = ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }
    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << filePath << (is64Bit ? ": x64" : ": x86") << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    if (importTableRVA == 0) {
        //std::cerr << "No import table found." << std::endl;
        UnmapViewOfFile(pMappedFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<BYTE*>(pMappedFile) + importTableRVA);

    std::cout << "Imported Functions:" << std::endl;

    while (importDescriptor->Name != 0) {
        char* dllName = reinterpret_cast<char*>(reinterpret_cast<BYTE*>(pMappedFile) + importDescriptor->Name);
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << dllName << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        PIMAGE_THUNK_DATA32 thunkData = reinterpret_cast<PIMAGE_THUNK_DATA32>(
            reinterpret_cast<BYTE*>(pMappedFile) + (importDescriptor->OriginalFirstThunk ? importDescriptor->OriginalFirstThunk : importDescriptor->FirstThunk));
        int a = 0;
        while (thunkData->u1.AddressOfData != 0) {
            if (thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                std::cout << "  Imported by Ordinal: " << IMAGE_ORDINAL32(thunkData->u1.Ordinal) << std::endl;
            }
            else {
                PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                    reinterpret_cast<BYTE*>(pMappedFile) + thunkData->u1.AddressOfData);

                if (importByName && importByName->Name) {
                    a += 1;
                    std::cout << a << "\t"
                        << std::setw(40) << std::left << importByName->Name << std::endl;
                }
            }
            ++thunkData;
        }
        ++importDescriptor;
    }

    UnmapViewOfFile(pMappedFile);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return;
}
