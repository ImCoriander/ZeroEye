#include <map>
#include "EModule.hpp"


void DisplayHelp() {

    std::cout << "Usage: ZeroEye [options]" << std::endl;
    std::cout << "options:" << std::endl;
    std::cout << "  -h\t<使用帮助>" << std::endl;
    std::cout << "  -i\t<PE  路径>\t#列出Exe的导入表" << std::endl;
    std::cout << "  -p\t<文件目录>\t#自动搜索文件路径下可劫持利用的白名单" << std::endl;
    std::cout << "  -s\t<签名校验>\t#仅对数字签名exe进行探测" << std::endl;
    std::cout << "  -e\t<独立 EXE>\t#仅列出系统系统dll的exe" << std::endl;
    std::cout << "  -d\t<生成模板>\t#生成dll模板" << std::endl;
    std::cout << "  -x\t<指定架构>\t#指定想要的架构（86/64）,为空则扫描两种架构" << std::endl;
    std::cout << "  -g\t<排除依赖>\t#排除指定dll的程序" << std::endl;
    std::cout << "  -IM\t<PE  路径>\t#查看导入表" << std::endl;
    std::cout << "  -EX\t<PE  路径>\t#查看导出表" << std::endl;
    std::cout << "example:" << std::endl;
    std::cout << "  ZeroEye.exe -i a.exe\t\t\t\t\t   #显示exe导入表" << std::endl;
    std::cout << "  ZeroEye.exe -p c:\\\t\t\t\t\t   #扫描c盘下所有exe" << std::endl;
    std::cout << "  ZeroEye.exe -d a.dll\t\t\t\t\t   #对指定dll生成模板,存放与当前路径" << std::endl;
    std::cout << "  ZeroEye.exe -IM/-EX a.exe/a.dll\t\t\t   #查看导入表/导出表" << std::endl;
    std::cout << "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\"\t   #扫描c盘下所有exe,并且仅扫描64位有数字签名的程序" << std::endl;
    std::cout << "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\" -e  #与上面的效果大致相同，-e仅寻找依赖系统dll的exe" << std::endl;

}
int main(int argc, char* argv[]) {
    std::cout << R"(
  _____                        _____                
 |__  /   ___   _ __    ___   | ____|  _   _    ___ 
   / /   / _ \ | '__|  / _ \  |  _|   | | | |  / _ \
  / /_  |  __/ | |    | (_) | | |___  | |_| | |  __/
 /____|  \___| |_|     \___/  |_____|  \__, |  \___|
                                       |___/ Ver`3.5              

    Github:https://github.com/ImCoriander/ZeroEye
    公众号：**零攻防**
)" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    if (argc < 2) {
        DisplayHelp();
        return 1;
    }
    std::map<std::string, std::string> parsedArgs;

    bool isSign = false;
    bool isExe = false;
    int is64 = 0;
    std::vector<std::string> result;
    // 参数解析
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h") {
            DisplayHelp();
            return 0;
        }
        else if (arg == "-s") {
            isSign = true;
        }
        else if (arg == "-e") {
            isExe = true;
        }
        else if (arg == "-i" || arg == "-p" || arg == "-d" || arg == "-x" || arg == "-g" || arg == "-IM" || arg == "-EX") {
            if (i + 1 < argc) {
                parsedArgs[arg] = argv[++i];
            }
            else {
                std::cerr << "Missing value for option: " << arg << std::endl;
                DisplayHelp();
                return 1;
            }
        }
        else {
            std::cerr << "Unknown option: " << arg << std::endl;
            DisplayHelp();
            return 1;
        }
    }


    // 调度功能
    if (parsedArgs.find("-i") != parsedArgs.end()) {
        std::vector<std::string> DllList;
        bool is64Bit;
        std::filesystem::path filename = parsedArgs["-i"];

        ViewImportedDLLs(filename.string().c_str(), DllList, is64Bit, 0);
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
        getFiles_and_view(parsedArgs["-p"].c_str(), is64, isSign,isExe, result);
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

    // 计算运行时间
    std::chrono::duration<double> duration = end - start;
    // 将总时间转换为分钟和秒
    int minutes = std::chrono::duration_cast<std::chrono::minutes>(duration).count();
    int seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count() % 60;

    // 输出运行时间（分秒格式）
    std::cout << "\n[*] 用时: " << minutes << "m " << seconds << "s" << std::endl;

    return 0;
}
