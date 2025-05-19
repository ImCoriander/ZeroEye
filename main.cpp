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
    std::cout << lang.viewImports << std::endl;
    std::cout << lang.viewExports << std::endl;
    std::cout << lang.excludeConsole << std::endl;
    if (flag)
    {
        std::cout << lang.examples << std::endl;
        std::cout << lang.showImports << std::endl;
        std::cout << lang.scanDirExe << std::endl;
        std::cout << lang.analyzeDll << std::endl;
        std::cout << lang.viewImportsExports << std::endl;
        std::cout << lang.scanWithOptions << std::endl;
        std::cout << lang.scanWithExclude << std::endl;
        std::cout << lang.scanWithExcludeNoConsole << std::endl;
    }

}
int main(int argc, char* argv[]) {
    system("cls");
    LanguageStrings lang = LanguageManager::GetStrings();
    std::cout << R"(
  _____                        _____                
 |__  /   ___   _ __    ___   | ____|  _   _    ___ 
   / /   / _ \ | '__|  / _ \  |  _|   | | | |  / _ \
  / /_  |  __/ | |    | (_) | | |___  | |_| | |  __/
 /____|  \___| |_|     \___/  |_____|  \__, |  \___|
                                       |___/ Ver`3.6              

    Github:https://github.com/ImCoriander/ZeroEye
    )" << lang.Owner <<  std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    if (argc < 2) {

        DisplayHelp(false);
        return 1;
    }
    std::map<std::string, std::string> parsedArgs;

    bool isSign = false;
    bool isExe = false;
    bool isGui = false;
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
        else if (arg == "-nc") {
            isGui = true;
        }
        else if (arg == "-i" || arg == "-p" || arg == "-d" || arg == "-x" || arg == "-g" || arg == "-IM" || arg == "-EX") {
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


    // ���ȹ���
    if (parsedArgs.find("-i") != parsedArgs.end()) {
        std::vector<std::string> DllList;
        bool is64Bit;
        std::filesystem::path filename = parsedArgs["-i"];
        bool flag;
        ViewImportedDLLs(filename.string().c_str(), DllList, is64Bit, 0, flag);
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "\t\t" << filename.stem().string() << " is " << (is64Bit ? "x64" : "x86") << "\n" << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        Exe_Output(filename, DllList);
    }

    if (parsedArgs.find("-x") != parsedArgs.end()) {
        std::string value = parsedArgs["-x"];
        if (value == "64") {
            is64 = 1;
        }
        else if (value == "86") {
            is64 = 2;
        }
        else {
            is64 = 0;
        }
    }
    if (parsedArgs.find("-g") != parsedArgs.end()) {
        std::string value = parsedArgs["-g"];
        result = SplitString(value, "|");
    }
    if (parsedArgs.find("-p") != parsedArgs.end()) {
        getFiles_and_view(parsedArgs["-p"].c_str(), is64, isGui, isSign,isExe, result);
    }

    if (parsedArgs.find("-d") != parsedArgs.end()) {
        std::string DemoFile = parsedArgs["-d"];
        std::string txtFile = ((std::filesystem::path)DemoFile).stem().string() + ".txt";

        EchoFunc(DemoFile, txtFile, true);
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "\n[+] Successful WriteTo : " << txtFile << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    if (parsedArgs.find("-IM") != parsedArgs.end()) {
        ListImportedFunctions(parsedArgs["-IM"].c_str());
    }

    if (parsedArgs.find("-EX") != parsedArgs.end()) {
        std::vector<std::string> Funclist;
        ListExportedFunctions(parsedArgs["-EX"].c_str(), false, Funclist);
    }




    // 记录结束时间
    auto end = std::chrono::high_resolution_clock::now();

    // 计算执行时间
    std::chrono::duration<double> duration = end - start;
    // 将时间转换为分钟和秒
    int minutes = std::chrono::duration_cast<std::chrono::minutes>(duration).count();
    int seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count() % 60;

    // 输出执行时间（使用语言管理器）
    
    std::cout << "\n[*] " << lang.executionTime << minutes << lang.minutes << " " << seconds << lang.seconds << std::endl;

    return 0;
}
