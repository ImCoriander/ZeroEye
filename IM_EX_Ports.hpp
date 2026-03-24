#pragma once
#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "PEFile.hpp"

void SetConsoleColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

// ============================================================
// Export table viewer — now outputs both decorated + undecorated
// Returns vector of ExportedFunction for programmatic use
// ============================================================
std::vector<ExportedFunction> ListExportedFunctions(const std::string& filePath, bool silent) {
    std::vector<ExportedFunction> result;

    PEFile pe(filePath);
    if (!pe.isValid()) return result;

    if (!silent) {
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << filePath << (pe.is64Bit() ? ": x64" : ": x86") << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    result = pe.readExports();

    if (!silent && !result.empty()) {
        std::string dllName = pe.readExportDllName();
        std::cout << "Exported Functions:" << std::endl;
        SetConsoleColor(FOREGROUND_GREEN);
        if (!dllName.empty()) std::cout << dllName << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        int idx = 0;
        for (const auto& e : result) {
            std::cout << ++idx << "\t"
                      << e.decoratedName << "\t"
                      << e.undecoratedName
                      << "\tRVA: 0x" << std::hex << e.rva << std::dec
                      << "\tOrdinal: " << e.ordinal
                      << std::endl;
        }
    }

    return result;
}

// ============================================================
// Import table viewer — fixed for 64-bit thunk data
// ============================================================
void ListImportedFunctions(const std::string& filePath) {
    PEFile pe(filePath);
    if (!pe.isValid()) return;

    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << filePath << (pe.is64Bit() ? ": x64" : ": x86") << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    DWORD importRVA = pe.getDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importRVA == 0) return;

    auto* importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pe.fromRVA(importRVA));
    if (!importDesc) return;

    std::cout << "Imported Functions:" << std::endl;

    while (importDesc->Name != 0) {
        auto* dllName = reinterpret_cast<char*>(pe.fromRVA(importDesc->Name));
        if (!dllName) break;

        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << dllName << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        DWORD thunkRVA = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
        int idx = 0;

        if (pe.is64Bit()) {
            // FIX: use 64-bit thunk data for x64 PE
            auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(pe.fromRVA(thunkRVA));
            if (!thunk) { importDesc++; continue; }
            while (thunk->u1.AddressOfData != 0) {
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    std::cout << "  Imported by Ordinal: " << IMAGE_ORDINAL64(thunk->u1.Ordinal) << std::endl;
                } else {
                    auto* byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        pe.fromRVA((DWORD)(thunk->u1.AddressOfData)));
                    if (byName && byName->Name[0]) {
                        std::cout << ++idx << "\t"
                                  << std::setw(40) << std::left << byName->Name << std::endl;
                    }
                }
                thunk++;
            }
        } else {
            // 32-bit thunk data
            auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(pe.fromRVA(thunkRVA));
            if (!thunk) { importDesc++; continue; }
            while (thunk->u1.AddressOfData != 0) {
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                    std::cout << "  Imported by Ordinal: " << IMAGE_ORDINAL32(thunk->u1.Ordinal) << std::endl;
                } else {
                    auto* byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        pe.fromRVA((DWORD)(thunk->u1.AddressOfData)));
                    if (byName && byName->Name[0]) {
                        std::cout << ++idx << "\t"
                                  << std::setw(40) << std::left << byName->Name << std::endl;
                    }
                }
                thunk++;
            }
        }
        importDesc++;
    }
}
