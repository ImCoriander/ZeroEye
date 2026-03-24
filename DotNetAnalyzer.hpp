#pragma once
// ============================================================
// DotNetAnalyzer.hpp — .NET Assembly Analysis for ZeroEye
//
// Parses .NET metadata (ECMA-335) to extract:
//   - ModuleRef table: P/Invoke native DLL targets
//   - AssemblyRef table: referenced assemblies
//   - Config/deps.json hijack detection
// ============================================================

#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <filesystem>
#include "PEFile.hpp"

namespace DotNet {

// ============================================================
// Result structure
// ============================================================
struct HijackResult {
    std::string exePath;
    bool is64Bit = false;
    bool isNetCore = false;
    bool configExists = false;
    bool configCanCreate = false;
    bool depsJsonExists = false;
    bool runtimeConfigExists = false;
    std::vector<std::string> pinvokeTargets;    // from ModuleRef
    std::vector<std::string> assemblyRefs;      // non-system AssemblyRef
    std::vector<std::string> allAssemblyRefs;   // all AssemblyRef (for Info.txt)
};

// ============================================================
// System assembly filter
// ============================================================
static bool IsSystemAssembly(const std::string& name) {
    if (name == "mscorlib" || name == "netstandard") return true;
    if (name == "System" || name == "WindowsBase" || name == "PresentationCore"
        || name == "PresentationFramework" || name == "UIAutomationProvider") return true;
    if (name.size() > 7 && name.substr(0, 7) == "System.") return true;

    // Only filter core Microsoft runtime assemblies, NOT app-specific ones
    // Microsoft.VisualStudio.*, Microsoft.Build.*, etc. are sideloadable
    if (name.size() > 10 && name.substr(0, 10) == "Microsoft.") {
        // These are true system/runtime assemblies (GAC)
        if (name == "Microsoft.CSharp" ||
            (name.size() > 16 && name.substr(0, 16) == "Microsoft.Win32.") ||
            (name.size() > 21 && name.substr(0, 21) == "Microsoft.Extensions.")) return true;
        // Everything else (Microsoft.VisualStudio.*, Microsoft.Build.*, etc.) is potentially sideloadable
        return false;
    }
    return false;
}

// ============================================================
// .NET Metadata column types for row size calculation
// ============================================================
enum ColType {
    Fixed2,     // 2 bytes
    Fixed4,     // 4 bytes
    StringIdx,  // 2 or 4 based on HeapSizes bit 0
    GuidIdx,    // 2 or 4 based on HeapSizes bit 1
    BlobIdx,    // 2 or 4 based on HeapSizes bit 2
    // Simple table index (2 or 4 based on row count of target table)
    Idx_TypeDef, Idx_Field, Idx_MethodDef, Idx_Param,
    Idx_Event, Idx_Property, Idx_ModuleRef, Idx_AssemblyRef, Idx_GenericParam,
    // Coded indices
    Coded_TypeDefOrRef, Coded_HasConstant, Coded_HasCustomAttribute,
    Coded_HasFieldMarshal, Coded_HasDeclSecurity, Coded_MemberRefParent,
    Coded_HasSemantics, Coded_MethodDefOrRef, Coded_MemberForwarded,
    Coded_Implementation, Coded_CustomAttributeType, Coded_ResolutionScope,
    Coded_TypeOrMethodDef,
};

struct TableDef {
    int colCount;
    ColType cols[9]; // max 9 columns per table
};

// ECMA-335 table definitions (tables 0x00 - 0x2C)
// Gaps (0x03, 0x05, 0x07, 0x13, 0x16) have 0 columns
static const TableDef TABLE_DEFS[] = {
    /* 0x00 Module */          {5, {Fixed2, StringIdx, GuidIdx, GuidIdx, GuidIdx}},
    /* 0x01 TypeRef */         {3, {Coded_ResolutionScope, StringIdx, StringIdx}},
    /* 0x02 TypeDef */         {6, {Fixed4, StringIdx, StringIdx, Coded_TypeDefOrRef, Idx_Field, Idx_MethodDef}},
    /* 0x03 FieldPtr */        {0, {}},
    /* 0x04 Field */           {3, {Fixed2, StringIdx, BlobIdx}},
    /* 0x05 MethodPtr */       {0, {}},
    /* 0x06 MethodDef */       {6, {Fixed4, Fixed2, Fixed2, StringIdx, BlobIdx, Idx_Param}},
    /* 0x07 ParamPtr */        {0, {}},
    /* 0x08 Param */           {3, {Fixed2, Fixed2, StringIdx}},
    /* 0x09 InterfaceImpl */   {2, {Idx_TypeDef, Coded_TypeDefOrRef}},
    /* 0x0A MemberRef */       {3, {Coded_MemberRefParent, StringIdx, BlobIdx}},
    /* 0x0B Constant */        {3, {Fixed2, Coded_HasConstant, BlobIdx}},
    /* 0x0C CustomAttribute */ {3, {Coded_HasCustomAttribute, Coded_CustomAttributeType, BlobIdx}},
    /* 0x0D FieldMarshal */    {2, {Coded_HasFieldMarshal, BlobIdx}},
    /* 0x0E DeclSecurity */    {3, {Fixed2, Coded_HasDeclSecurity, BlobIdx}},
    /* 0x0F ClassLayout */     {3, {Fixed2, Fixed4, Idx_TypeDef}},
    /* 0x10 FieldLayout */     {2, {Fixed4, Idx_Field}},
    /* 0x11 StandAloneSig */   {1, {BlobIdx}},
    /* 0x12 EventMap */        {2, {Idx_TypeDef, Idx_Event}},
    /* 0x13 EventPtr */        {0, {}},
    /* 0x14 Event */           {3, {Fixed2, StringIdx, Coded_TypeDefOrRef}},
    /* 0x15 PropertyMap */     {2, {Idx_TypeDef, Idx_Property}},
    /* 0x16 PropertyPtr */     {0, {}},
    /* 0x17 Property */        {3, {Fixed2, StringIdx, BlobIdx}},
    /* 0x18 MethodSemantics */ {3, {Fixed2, Idx_MethodDef, Coded_HasSemantics}},
    /* 0x19 MethodImpl */      {3, {Idx_TypeDef, Coded_MethodDefOrRef, Coded_MethodDefOrRef}},
    /* 0x1A ModuleRef */       {1, {StringIdx}},
    /* 0x1B TypeSpec */        {1, {BlobIdx}},
    /* 0x1C ImplMap */         {4, {Fixed2, Coded_MemberForwarded, StringIdx, Idx_ModuleRef}},
    /* 0x1D FieldRVA */        {2, {Fixed4, Idx_Field}},
    /* 0x1E (gap) */           {0, {}},
    /* 0x1F (gap) */           {0, {}},
    /* 0x20 Assembly */        {9, {Fixed4, Fixed2, Fixed2, Fixed2, Fixed2, Fixed4, BlobIdx, StringIdx, StringIdx}},
    /* 0x21 AssemblyProcessor*/{1, {Fixed4}},
    /* 0x22 AssemblyOS */      {3, {Fixed4, Fixed4, Fixed4}},
    /* 0x23 AssemblyRef */     {9, {Fixed2, Fixed2, Fixed2, Fixed2, Fixed4, BlobIdx, StringIdx, StringIdx, BlobIdx}},
    /* 0x24 AssemblyRefProcessor */ {2, {Fixed4, Idx_AssemblyRef}},
    /* 0x25 AssemblyRefOS */   {4, {Fixed4, Fixed4, Fixed4, Idx_AssemblyRef}},
    /* 0x26 File */            {3, {Fixed4, StringIdx, BlobIdx}},
    /* 0x27 ExportedType */    {5, {Fixed4, Fixed4, StringIdx, StringIdx, Coded_Implementation}},
    /* 0x28 ManifestResource */{4, {Fixed4, Fixed4, StringIdx, Coded_Implementation}},
    /* 0x29 NestedClass */     {2, {Idx_TypeDef, Idx_TypeDef}},
    /* 0x2A GenericParam */    {4, {Fixed2, Fixed2, Coded_TypeOrMethodDef, StringIdx}},
    /* 0x2B MethodSpec */      {2, {Coded_MethodDefOrRef, BlobIdx}},
    /* 0x2C GenericParamConstraint */ {2, {Idx_GenericParam, Coded_TypeDefOrRef}},
};
static const int TABLE_COUNT = sizeof(TABLE_DEFS) / sizeof(TABLE_DEFS[0]);

// ============================================================
// Coded index definitions: {tag_bits, referenced_table_ids[]}
// ============================================================
struct CodedIndexDef {
    int tagBits;
    std::vector<int> tableIds;
};

static CodedIndexDef GetCodedIndexDef(ColType ct) {
    switch (ct) {
    case Coded_TypeDefOrRef:       return {2, {0x02, 0x01, 0x1B}};
    case Coded_HasConstant:        return {2, {0x04, 0x08, 0x17}};
    case Coded_HasCustomAttribute: return {5, {0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00,
                                               0x0E, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A}};
    case Coded_HasFieldMarshal:    return {1, {0x04, 0x08}};
    case Coded_HasDeclSecurity:    return {2, {0x02, 0x06, 0x20}};
    case Coded_MemberRefParent:    return {3, {0x02, 0x01, 0x1A, 0x06, 0x1B}};
    case Coded_HasSemantics:       return {1, {0x14, 0x17}};
    case Coded_MethodDefOrRef:     return {1, {0x06, 0x0A}};
    case Coded_MemberForwarded:    return {1, {0x04, 0x06}};
    case Coded_Implementation:     return {2, {0x26, 0x23, 0x27}};
    case Coded_CustomAttributeType:return {3, {-1, -1, 0x06, 0x0A, -1}}; // only indices 2,3 are valid
    case Coded_ResolutionScope:    return {2, {0x00, 0x1A, 0x23, 0x01}};
    case Coded_TypeOrMethodDef:    return {1, {0x02, 0x06}};
    default: return {0, {}};
    }
}

// ============================================================
// Compute column width in bytes
// ============================================================
static int GetColumnWidth(ColType ct, BYTE heapSizes, const DWORD rowCounts[64]) {
    switch (ct) {
    case Fixed2: return 2;
    case Fixed4: return 4;
    case StringIdx: return (heapSizes & 0x01) ? 4 : 2;
    case GuidIdx:   return (heapSizes & 0x02) ? 4 : 2;
    case BlobIdx:   return (heapSizes & 0x04) ? 4 : 2;
    // Simple table indices
    case Idx_TypeDef:    return rowCounts[0x02] > 0xFFFF ? 4 : 2;
    case Idx_Field:      return rowCounts[0x04] > 0xFFFF ? 4 : 2;
    case Idx_MethodDef:  return rowCounts[0x06] > 0xFFFF ? 4 : 2;
    case Idx_Param:      return rowCounts[0x08] > 0xFFFF ? 4 : 2;
    case Idx_Event:      return rowCounts[0x14] > 0xFFFF ? 4 : 2;
    case Idx_Property:   return rowCounts[0x17] > 0xFFFF ? 4 : 2;
    case Idx_ModuleRef:  return rowCounts[0x1A] > 0xFFFF ? 4 : 2;
    case Idx_AssemblyRef:return rowCounts[0x23] > 0xFFFF ? 4 : 2;
    case Idx_GenericParam:return rowCounts[0x2A] > 0xFFFF ? 4 : 2;
    default: break;
    }

    // Coded indices
    auto def = GetCodedIndexDef(ct);
    if (def.tagBits == 0) return 2;
    DWORD maxRows = 0;
    for (int tid : def.tableIds) {
        if (tid >= 0 && tid < 64) {
            maxRows = (std::max)(maxRows, rowCounts[tid]);
        }
    }
    int valueBits = 16 - def.tagBits;
    return (maxRows < ((DWORD)1 << valueBits)) ? 2 : 4;
}

// ============================================================
// Compute row size for a table
// ============================================================
static int GetTableRowSize(int tableId, BYTE heapSizes, const DWORD rowCounts[64]) {
    if (tableId < 0 || tableId >= TABLE_COUNT) return 0;
    const auto& td = TABLE_DEFS[tableId];
    int size = 0;
    for (int i = 0; i < td.colCount; i++) {
        size += GetColumnWidth(td.cols[i], heapSizes, rowCounts);
    }
    return size;
}

// ============================================================
// Read a 2 or 4 byte index from a buffer
// ============================================================
static DWORD ReadIndex(const BYTE* p, int width) {
    if (width == 4) return *(const DWORD*)p;
    return *(const WORD*)p;
}

// ============================================================
// Read string from #Strings heap
// ============================================================
static std::string ReadString(const BYTE* stringsBase, DWORD stringsSize, DWORD offset) {
    if (!stringsBase || stringsSize == 0 || offset >= stringsSize) return "";
    const char* s = reinterpret_cast<const char*>(stringsBase + offset);
    // Find null terminator within bounds
    DWORD maxLen = stringsSize - offset;
    size_t len = 0;
    while (len < maxLen && s[len] != '\0') len++;
    return std::string(s, len);
}

// ============================================================
// Main analysis function
// ============================================================
static HijackResult Analyze(const std::string& exePath, PEFile& pe) {
    HijackResult result;
    result.exePath = exePath;
    result.is64Bit = pe.is64Bit();

    std::filesystem::path exeFs(exePath);
    std::string stem = exeFs.stem().string();
    std::filesystem::path dir = exeFs.parent_path();

    // Check config files
    std::filesystem::path configPath = std::filesystem::path(exePath + ".config");
    result.configExists = std::filesystem::exists(configPath);
    result.configCanCreate = !result.configExists;

    std::filesystem::path depsPath = dir / (stem + ".deps.json");
    result.depsJsonExists = std::filesystem::exists(depsPath);

    std::filesystem::path runtimePath = dir / (stem + ".runtimeconfig.json");
    result.runtimeConfigExists = std::filesystem::exists(runtimePath);
    result.isNetCore = result.runtimeConfigExists || result.depsJsonExists;

    // Get CLR header
    DWORD cor20RVA = pe.getDataDirectoryRVA(14);
    if (!cor20RVA) return result;

    struct COR20_HEADER {
        DWORD cb;
        WORD MajorRuntimeVersion;
        WORD MinorRuntimeVersion;
        DWORD MetaDataRVA;
        DWORD MetaDataSize;
        DWORD Flags;
        DWORD EntryPointToken;
        DWORD ResourcesRVA;
        DWORD ResourcesSize;
        DWORD StrongNameSignatureRVA;
        DWORD StrongNameSignatureSize;
    };

    auto* cor20 = reinterpret_cast<COR20_HEADER*>(pe.fromRVA(cor20RVA));
    if (!cor20) return result;

    DWORD metaRVA = cor20->MetaDataRVA;
    DWORD metaSize = cor20->MetaDataSize;
    if (!metaRVA || !metaSize) return result;

    BYTE* metaBase = pe.fromRVA(metaRVA);
    if (!metaBase) return result;

    // Validate metadata signature: 0x424A5342
    if (*(DWORD*)metaBase != 0x424A5342) return result;

    // Parse metadata root header
    DWORD versionLen = *(DWORD*)(metaBase + 12);
    DWORD offset = 16 + ((versionLen + 3) & ~3); // version string padded to 4 bytes
    // Skip flags (2 bytes), read stream count (2 bytes)
    WORD streamCount = *(WORD*)(metaBase + offset + 2);
    offset += 4;

    // Parse stream headers
    BYTE* tablesStream = nullptr;
    DWORD tablesStreamSize = 0;
    BYTE* stringsStream = nullptr;
    DWORD stringsStreamSize = 0;

    for (WORD i = 0; i < streamCount; i++) {
        DWORD sOffset = *(DWORD*)(metaBase + offset);
        DWORD sSize = *(DWORD*)(metaBase + offset + 4);
        const char* sName = reinterpret_cast<const char*>(metaBase + offset + 8);

        if (strcmp(sName, "#~") == 0 || strcmp(sName, "#-") == 0) {
            tablesStream = metaBase + sOffset;
            tablesStreamSize = sSize;
        } else if (strcmp(sName, "#Strings") == 0) {
            stringsStream = metaBase + sOffset;
            stringsStreamSize = sSize;
        }

        // Advance: 8 bytes + name length padded to 4 bytes
        size_t nameLen = strlen(sName) + 1;
        nameLen = (nameLen + 3) & ~3;
        offset += 8 + (DWORD)nameLen;
    }

    if (!tablesStream || !stringsStream) return result;

    // Parse #~ stream header
    BYTE heapSizes = tablesStream[6];
    ULONGLONG validMask = *(ULONGLONG*)(tablesStream + 8);
    // ULONGLONG sortedMask = *(ULONGLONG*)(tablesStream + 16); // not needed

    // Read row counts for each present table
    DWORD rowCounts[64] = {};
    DWORD rowsOffset = 24;
    for (int t = 0; t < 64; t++) {
        if (validMask & (1ULL << t)) {
            rowCounts[t] = *(DWORD*)(tablesStream + rowsOffset);
            rowsOffset += 4;
        }
    }

    // Now walk through table data to find ModuleRef (0x1A) and AssemblyRef (0x23)
    DWORD dataOffset = rowsOffset; // start of actual table rows

    int stringIdxWidth = (heapSizes & 0x01) ? 4 : 2;

    for (int t = 0; t < 64; t++) {
        if (!(validMask & (1ULL << t))) continue;
        if (rowCounts[t] == 0) continue;

        int rowSize = GetTableRowSize(t, heapSizes, rowCounts);
        if (rowSize == 0) {
            // Unknown table — can't continue safely
            break;
        }

        if (t == 0x1A) {
            // ModuleRef table: each row is just a String index (the DLL name)
            for (DWORD r = 0; r < rowCounts[t]; r++) {
                BYTE* row = tablesStream + dataOffset + r * rowSize;
                DWORD nameIdx = ReadIndex(row, stringIdxWidth);
                std::string name = ReadString(stringsStream, stringsStreamSize, nameIdx);
                if (!name.empty()) {
                    result.pinvokeTargets.push_back(name);
                }
            }
        }

        if (t == 0x23) {
            // AssemblyRef table columns:
            // MajorVersion(2), MinorVersion(2), BuildNumber(2), RevisionNumber(2),
            // Flags(4), PublicKeyOrToken(Blob), Name(String), Culture(String), HashValue(Blob)
            int blobWidth = (heapSizes & 0x04) ? 4 : 2;
            int nameOffset = 2 + 2 + 2 + 2 + 4 + blobWidth; // offset to Name column

            for (DWORD r = 0; r < rowCounts[t]; r++) {
                BYTE* row = tablesStream + dataOffset + r * rowSize;
                DWORD nameIdx = ReadIndex(row + nameOffset, stringIdxWidth);
                std::string name = ReadString(stringsStream, stringsStreamSize, nameIdx);
                if (!name.empty()) {
                    result.allAssemblyRefs.push_back(name);
                    if (!IsSystemAssembly(name)) {
                        result.assemblyRefs.push_back(name);
                    }
                }
            }
        }

        dataOffset += rowCounts[t] * rowSize;
    }

    return result;
}

// ============================================================
// Check if a .NET exe has any exploitable vectors
// ============================================================
static bool HasExploitableVectors(const HijackResult& r) {
    return r.configCanCreate || r.configExists || r.depsJsonExists
        || !r.pinvokeTargets.empty() || !r.assemblyRefs.empty();
}

} // namespace DotNet
