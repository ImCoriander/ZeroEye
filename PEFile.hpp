#pragma once
#include <Windows.h>
#include <dbghelp.h>
#include <string>
#include <vector>
#pragma comment(lib, "dbghelp.lib")

// ============================================================
// Export entry: holds both decorated and undecorated names
// ============================================================
struct ExportedFunction {
    std::string decoratedName;
    std::string undecoratedName;
    DWORD ordinal;
    DWORD rva;
};

// ============================================================
// RAII PE file wrapper — eliminates all manual cleanup code
// Opens file with PAGE_READONLY (no SEC_IMAGE) to avoid crash
// on malformed PE. Uses manual RVA→FileOffset conversion.
// ============================================================
class PEFile {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = NULL;
    LPVOID pBase = nullptr;
    bool m_valid = false;
    bool m_is64Bit = false;
    bool m_rawMapping = false;  // true if SEC_IMAGE failed, using raw PAGE_READONLY
    DWORD m_fileSize = 0;
    DWORD m_imageSize = 0;  // SizeOfImage from optional header (virtual size after SEC_IMAGE mapping)
    PIMAGE_NT_HEADERS m_ntHeaders = nullptr;
    PIMAGE_SECTION_HEADER m_sections = nullptr;
    WORD m_numSections = 0;

public:
    explicit PEFile(const std::string& filePath) {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

        hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return;

        m_fileSize = GetFileSize(hFile, NULL);
        if (m_fileSize < sizeof(IMAGE_DOS_HEADER)) { close(); return; }

        // SEC_IMAGE: OS maps PE with section alignment (RVA == offset into mapping)
        // Try SEC_IMAGE first; fall back to PAGE_READONLY for malformed PE
        hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        if (!hMapping) {
            // Fallback for malformed PE
            hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
            m_rawMapping = true;
        }
        if (!hMapping) { close(); return; }

        pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!pBase) { close(); return; }

        // Validate DOS header
        auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { close(); return; }

        DWORD peOffset = dos->e_lfanew;
        if (peOffset + sizeof(IMAGE_NT_HEADERS32) > m_fileSize) { close(); return; }

        // Validate NT header
        m_ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(ptr(peOffset));
        if (m_ntHeaders->Signature != IMAGE_NT_SIGNATURE) { close(); return; }

        m_is64Bit = (m_ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
        m_numSections = m_ntHeaders->FileHeader.NumberOfSections;

        // Get SizeOfImage for SEC_IMAGE bounds checking
        if (m_is64Bit)
            m_imageSize = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_ntHeaders)->OptionalHeader.SizeOfImage;
        else
            m_imageSize = reinterpret_cast<PIMAGE_NT_HEADERS32>(m_ntHeaders)->OptionalHeader.SizeOfImage;

        // Section headers follow optional header
        DWORD sectionsOffset = peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                             + m_ntHeaders->FileHeader.SizeOfOptionalHeader;
        m_sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(ptr(sectionsOffset));

        m_valid = true;
    }

    ~PEFile() { close(); }

    // Non-copyable
    PEFile(const PEFile&) = delete;
    PEFile& operator=(const PEFile&) = delete;

    bool isValid() const { return m_valid; }
    bool is64Bit() const { return m_is64Bit; }
    bool isDotNet() const { return m_valid && getDataDirectoryRVA(14) != 0; }
    LPVOID base() const { return pBase; }
    DWORD fileSize() const { return m_fileSize; }

    // Get a pointer at a raw file offset
    BYTE* ptr(DWORD fileOffset) const {
        return reinterpret_cast<BYTE*>(pBase) + fileOffset;
    }

    // Convert RVA to file offset. With SEC_IMAGE mapping, RVA == offset (no conversion needed).
    DWORD rvaToOffset(DWORD rva) const {
        if (!m_rawMapping) return rva;  // SEC_IMAGE: RVA is already mapped correctly
        if (!m_sections || !m_numSections) return rva;
        for (WORD i = 0; i < m_numSections; i++) {
            DWORD va = m_sections[i].VirtualAddress;
            DWORD size = m_sections[i].Misc.VirtualSize;
            if (size == 0) size = m_sections[i].SizeOfRawData;
            if (rva >= va && rva < va + size) {
                return rva - va + m_sections[i].PointerToRawData;
            }
        }
        return rva; // Fallback: data in PE header where RVA == file offset
    }

    // Get a pointer from an RVA
    BYTE* fromRVA(DWORD rva) const {
        DWORD off = rvaToOffset(rva);
        // SEC_IMAGE: virtual size > file size, use SizeOfImage for bounds check
        DWORD limit = m_rawMapping ? m_fileSize : m_imageSize;
        if (limit == 0) limit = m_fileSize;
        if (off >= limit) return nullptr;
        return ptr(off);
    }

    // Get data directory RVA (handles 32/64 bit)
    DWORD getDataDirectoryRVA(int index) const {
        if (!m_valid) return 0;
        if (m_is64Bit) {
            auto* nt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_ntHeaders);
            if (index >= (int)nt64->OptionalHeader.NumberOfRvaAndSizes) return 0;
            return nt64->OptionalHeader.DataDirectory[index].VirtualAddress;
        } else {
            auto* nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(m_ntHeaders);
            if (index >= (int)nt32->OptionalHeader.NumberOfRvaAndSizes) return 0;
            return nt32->OptionalHeader.DataDirectory[index].VirtualAddress;
        }
    }

    DWORD getDataDirectorySize(int index) const {
        if (!m_valid) return 0;
        if (m_is64Bit) {
            auto* nt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_ntHeaders);
            if (index >= (int)nt64->OptionalHeader.NumberOfRvaAndSizes) return 0;
            return nt64->OptionalHeader.DataDirectory[index].Size;
        } else {
            auto* nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(m_ntHeaders);
            if (index >= (int)nt32->OptionalHeader.NumberOfRvaAndSizes) return 0;
            return nt32->OptionalHeader.DataDirectory[index].Size;
        }
    }

    WORD getSubsystem() const {
        if (!m_valid) return 0;
        if (m_is64Bit) {
            return reinterpret_cast<PIMAGE_NT_HEADERS64>(m_ntHeaders)->OptionalHeader.Subsystem;
        } else {
            return reinterpret_cast<PIMAGE_NT_HEADERS32>(m_ntHeaders)->OptionalHeader.Subsystem;
        }
    }

    // Read exported functions (both decorated and undecorated names)
    std::vector<ExportedFunction> readExports() const {
        std::vector<ExportedFunction> result;
        if (!m_valid) return result;

        DWORD exportRVA = getDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (exportRVA == 0) return result;

        auto* exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(fromRVA(exportRVA));
        if (!exportDir) return result;

        auto* nameRVAs    = reinterpret_cast<DWORD*>(fromRVA(exportDir->AddressOfNames));
        auto* funcRVAs    = reinterpret_cast<DWORD*>(fromRVA(exportDir->AddressOfFunctions));
        auto* ordinals    = reinterpret_cast<WORD*>(fromRVA(exportDir->AddressOfNameOrdinals));
        if (!nameRVAs || !funcRVAs || !ordinals) return result;

        // Forwarded export detection: RVA points inside export directory
        DWORD exportDirEnd = exportRVA + getDataDirectorySize(IMAGE_DIRECTORY_ENTRY_EXPORT);

        char undecBuf[4096]; // Buffer for undecorated name (4096 >> old 1024)

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            auto* funcName = reinterpret_cast<char*>(fromRVA(nameRVAs[i]));
            if (!funcName) continue;

            DWORD funcRVA = funcRVAs[ordinals[i]];

            ExportedFunction entry;
            entry.decoratedName = funcName;
            entry.rva = funcRVA;
            entry.ordinal = exportDir->Base + ordinals[i];

            // Undecorate
            if (UnDecorateSymbolName(funcName, undecBuf, sizeof(undecBuf), UNDNAME_COMPLETE)) {
                entry.undecoratedName = undecBuf;
            } else {
                entry.undecoratedName = funcName; // Fallback: use raw name
            }

            result.push_back(std::move(entry));
        }

        return result;
    }

    // Read DLL name from export directory
    std::string readExportDllName() const {
        if (!m_valid) return "";
        DWORD exportRVA = getDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (exportRVA == 0) return "";
        auto* exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(fromRVA(exportRVA));
        if (!exportDir || !exportDir->Name) return "";
        auto* name = reinterpret_cast<char*>(fromRVA(exportDir->Name));
        return name ? name : "";
    }

    // Read imported DLL names
    std::vector<std::string> readImportDlls() const {
        std::vector<std::string> result;
        if (!m_valid) return result;

        DWORD importRVA = getDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (importRVA == 0) return result;

        auto* importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(fromRVA(importRVA));
        if (!importDesc) return result;

        while (importDesc->Name != 0) {
            auto* dllName = reinterpret_cast<char*>(fromRVA(importDesc->Name));
            if (dllName && strlen(dllName) > 0) {
                result.push_back(dllName);
            }
            importDesc++;
        }

        return result;
    }

private:
    void close() {
        if (pBase) { UnmapViewOfFile(pBase); pBase = nullptr; }
        if (hMapping) { CloseHandle(hMapping); hMapping = NULL; }
        if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE; }
        m_valid = false;
    }
};
