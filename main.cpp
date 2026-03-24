#include <map>
#include "EModule.hpp"
#include "Language.hpp"


void DisplayHelp(bool flag) {
    LanguageStrings lang = LanguageManager::GetStrings();

    std::cout << lang.usage << std::endl;
    std::cout << lang.options << std::endl;
    std::cout << lang.help << std::endl;
    std::cout << lang.inputFile << std::endl;
    std::cout << lang.scanDir << std::endl;
    std::cout << lang.signatureCheck << std::endl;
    std::cout << lang.excludeSystem << std::endl;
    std::cout << lang.analyzeModule << std::endl;
    std::cout << lang.specifyArch << std::endl;
    std::cout << lang.excludeList << std::endl;
    std::cout << lang.scanType << std::endl;
    std::cout << lang.viewImports << std::endl;
    std::cout << lang.viewExports << std::endl;
    if (flag)
    {
        std::cout << lang.examples << std::endl;
        std::cout << lang.showImports << std::endl;
        std::cout << lang.showImportsDotNet << std::endl;
        std::cout << lang.scanDirExe << std::endl;
        std::cout << lang.analyzeDll << std::endl;
        std::cout << lang.analyzeDotNetExe << std::endl;
        std::cout << lang.scanTypeExamples << std::endl;
        std::cout << lang.viewImportsExports << std::endl;
        std::cout << lang.scanWithOptions << std::endl;
        std::cout << lang.scanWithExclude << std::endl;
    }

}

// Parse -t value into ScanType bitmask
int ParseScanType(const std::string& value) {
    int scanType = 0;
    auto parts = SplitString(value, ",");
    for (auto& p : parts) {
        // trim spaces
        while (!p.empty() && p.front() == ' ') p.erase(p.begin());
        while (!p.empty() && p.back() == ' ') p.pop_back();
        // to lower
        std::transform(p.begin(), p.end(), p.begin(), ::tolower);

        if (p == "gui")         scanType |= SCAN_GUI;
        else if (p == "cmd")    scanType |= SCAN_CMD;
        else if (p == "exe")    scanType |= SCAN_EXE;
        else if (p == "dotnet") scanType |= SCAN_DOTNET;
        else if (p == "sys")    scanType |= SCAN_SYS;
        else if (p == "all")    scanType |= SCAN_ALL;
        else {
            std::cerr << "Unknown scan type: " << p << std::endl;
            std::cerr << "Valid types: gui, cmd, exe, dotnet, sys, all" << std::endl;
            return -1;
        }
    }
    return scanType;
}

// Separate function for Phase 3 so SEH can wrap it
int RunActions(std::map<std::string, std::string>& parsedArgs,
               int is64, int scanType, bool isSign, bool isExe,
               std::vector<std::string>& result) {

    // -i: Auto-detect native PE vs .NET, show appropriate analysis
    if (parsedArgs.find("-i") != parsedArgs.end()) {
        std::string target = parsedArgs["-i"];
        PEFile pe(target);
        if (!pe.isValid()) {
            SetConsoleColor(FOREGROUND_RED);
            std::cerr << "[-] Cannot open PE file: " << target << std::endl;
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        else if (pe.isDotNet()) {
            auto dotnetResult = DotNet::Analyze(target, pe);
            FilterPInvokeTargets(dotnetResult);
            DotNet_Print_Analysis(dotnetResult);
        }
        else {
            std::filesystem::path filename = target;
            std::vector<std::string> DllList = pe.readImportDlls();
            SetConsoleColor(FOREGROUND_GREEN);
            std::cout << "\t\t" << filename.stem().string() << " is " << (pe.is64Bit() ? "x64" : "x86") << "\n" << std::endl;
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            Exe_Output(filename, DllList);
        }
    }

    // -p: Scan directory
    if (parsedArgs.find("-p") != parsedArgs.end()) {
        getFiles_and_view(parsedArgs["-p"].c_str(), is64, scanType, isSign, isExe, result);
    }

    // -d: Auto-detect native DLL vs .NET, generate appropriate templates
    if (parsedArgs.find("-d") != parsedArgs.end()) {
        std::string target = parsedArgs["-d"];
        PEFile pe(target);
        if (!pe.isValid()) {
            SetConsoleColor(FOREGROUND_RED);
            std::cerr << "[-] Cannot open PE file: " << target << std::endl;
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        else if (pe.isDotNet()) {
            auto dotnetResult = DotNet::Analyze(target, pe);
            FilterPInvokeTargets(dotnetResult);
            DotNet_Print_Analysis(dotnetResult);
            std::filesystem::path targetPath(target);
            GenerateHijackConfig(std::filesystem::current_path(),
                                 targetPath.filename().string(), dotnetResult);
        }
        else {
            GenerateAllTemplates(target);
        }
    }

    // -IM: View import table (function-level)
    if (parsedArgs.find("-IM") != parsedArgs.end()) {
        ListImportedFunctions(parsedArgs["-IM"]);
    }

    // -EX: View export table
    if (parsedArgs.find("-EX") != parsedArgs.end()) {
        ListExportedFunctions(parsedArgs["-EX"], false);
    }

    return 0;
}

// SEH wrapper
int RunActionsSafe(std::map<std::string, std::string>& parsedArgs,
                   int is64, int scanType, bool isSign, bool isExe,
                   std::vector<std::string>& result) {
    __try {
        return RunActions(parsedArgs, is64, scanType, isSign, isExe, result);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        SetConsoleColor(FOREGROUND_RED);
        if (code == EXCEPTION_STACK_OVERFLOW) {
            std::cerr << "\n[-] Stack overflow (directory too deep)" << std::endl;
        } else {
            std::cerr << "\n[-] Fatal exception: 0x" << std::hex << code << std::dec << std::endl;
        }
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        return 1;
    }
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    LanguageStrings lang = LanguageManager::GetStrings();
    std::cout << R"(
  _____                        _____
 |__  /   ___   _ __    ___   | ____|  _   _    ___
   / /   / _ \ | '__|  / _ \  |  _|   | | | |  / _ \
  / /_  |  __/ | |    | (_) | | |___  | |_| | |  __/
 /____|  \___| |_|     \___/  |_____|  \__, |  \___|
                                       |___/ Ver`5.0

    Github:https://github.com/ImCoriander/ZeroEye
    )" << lang.Owner <<  std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    if (argc < 2) {

        DisplayHelp(true);
        return 1;
    }

    // ============================================================
    // Phase 1: Parse ALL arguments first, execute NOTHING yet
    // ============================================================
    std::map<std::string, std::string> parsedArgs;

    bool isSign = false;
    bool isExe = false;
    int scanType = SCAN_ALL;  // default: scan everything
    int is64 = 0;
    std::vector<std::string> result;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            DisplayHelp(true);
            return 0;
        }
        else if (arg == "-s") {
            isSign = true;
        }
        else if (arg == "-e") {
            isExe = true;
        }
        else if (arg == "-i" || arg == "-p" || arg == "-d" || arg == "-x" || arg == "-g" || arg == "-t" || arg == "-IM" || arg == "-EX") {
            if (i + 1 < argc) {
                parsedArgs[arg] = argv[++i];
            }
            else {
                std::cerr << "Missing value for option: " << arg << std::endl;
                DisplayHelp(false);
                return 1;
            }
        }
        else {
            std::cerr << "Unknown option: " << arg << std::endl;
            return 1;
        }
    }

    // ============================================================
    // Phase 2: Process option modifiers BEFORE actions
    // ============================================================
    if (parsedArgs.find("-x") != parsedArgs.end()) {
        std::string value = parsedArgs["-x"];
        if (value == "64") is64 = 1;
        else if (value == "86") is64 = 2;
        else is64 = 0;
    }
    if (parsedArgs.find("-g") != parsedArgs.end()) {
        result = SplitString(parsedArgs["-g"], "|");
    }
    if (parsedArgs.find("-t") != parsedArgs.end()) {
        scanType = ParseScanType(parsedArgs["-t"]);
        if (scanType < 0) return 1;
    }

    // ============================================================
    // Phase 3: Execute actions (SEH protected)
    // ============================================================
    RunActionsSafe(parsedArgs, is64, scanType, isSign, isExe, result);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    int minutes = std::chrono::duration_cast<std::chrono::minutes>(duration).count();
    int seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count() % 60;
    std::cout << "\n[*] " << lang.executionTime << minutes << lang.minutes << " " << seconds << lang.seconds << std::endl;

    return 0;
}
