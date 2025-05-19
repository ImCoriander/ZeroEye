#pragma once
#include <Windows.h>
#include <string>

struct LanguageStrings {
    std::string usage;
    std::string options;
    std::string help;
    std::string inputFile;
    std::string scanDir;
    std::string signatureCheck;
    std::string excludeSystem;
    std::string analyzeModule;
    std::string specifyArch;
    std::string excludeList;
    std::string viewImports;
    std::string viewExports;
    std::string excludeConsole;
    std::string examples;
    std::string showImports;
    std::string scanDirExe;
    std::string analyzeDll;
    std::string viewImportsExports;
    std::string scanWithOptions;
    std::string scanWithExclude;
    std::string scanWithExcludeNoConsole;
    std::string programType;
    std::string consoleApp;
    std::string guiApp;
    std::string importedDlls;
    std::string noImportsFound;
    std::string errorFile;
    std::string executionTime;
    std::string minutes;
    std::string seconds;
    std::string Owner;
};

class LanguageManager {
public:
    static LanguageStrings GetStrings() {
        LanguageStrings strings;
        if (IsEnglishSystem()) {
            // English strings
            strings.usage = "Usage: ZeroEye [options]";
            strings.options = "options:";
            strings.help = "  -h\t<help|examples>\t\t\t\t\t#Display help information";
            strings.inputFile = "  -i\t<PE file>\t\t\t\t#List imported DLLs of the exe";
            strings.scanDir = "  -p\t<directory>\t\t\t\t#Automatically scan suspicious programs in the specified directory";
            strings.signatureCheck = "  -s\t<signature check>\t\t\t#Only scan signed exe programs";
            strings.excludeSystem = "  -e\t<exclude EXE>\t\t\t\t#Exclude system dlls and exes";
            strings.analyzeModule = "  -d\t<specified module>\t\t\t#Analyze dll module";
            strings.specifyArch = "  -x\t<specified architecture>\t\t#Specify the architecture to scan (x86/x64)";
            strings.excludeList = "  -g\t<exclude list>\t\t\t\t#Exclude specified dlls from scanning";
            strings.viewImports = "  -IM\t<PE file>\t\t\t\t#View import table";
            strings.viewExports = "  -EX\t<PE file>\t\t\t\t#View export table";
            strings.excludeConsole = "  -nc\t<exclude console>\t\t\t#Exclude console applications";
            strings.examples = "examples:";
            strings.showImports = "  ZeroEye.exe -i a.exe\t\t\t\t\t   #Show exe imports";
            strings.scanDirExe = "  ZeroEye.exe -p c:\\\t\t\t\t\t   #Scan exes in c drive";
            strings.analyzeDll = "  ZeroEye.exe -d a.dll\t\t\t\t\t   #Analyze specified dll module";
            strings.viewImportsExports = "  ZeroEye.exe -IM/-EX a.exe/a.dll\t\t\t   #View imports/exports";
            strings.scanWithOptions = "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\"\t   #Scan exes in c drive, only scan 64-bit signed programs";
            strings.scanWithExclude = "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\" -e  #Scan for exe that only requires system dlls";
            strings.scanWithExcludeNoConsole = "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\" -nc  #Same as above, exclude console applications";
            strings.programType = "Program Type: ";
            strings.consoleApp = "Console Application";
            strings.guiApp = "GUI Application";
            strings.importedDlls = "Imported DLLs:";
            strings.noImportsFound = "No Imported DLLs Found";
            strings.errorFile = "Error File";
            strings.executionTime = "Execution Time: ";
            strings.minutes = "m";
            strings.seconds = "s";
            strings.Owner = "WeChat Public account: ZeroDefense";
        } else {
            // Chinese strings
            strings.usage = "用法: ZeroEye [选项]";
            strings.options = "选项:";
            strings.help = "  -h\t<帮助|例子>\t\t\t\t#显示帮助信息";
            strings.inputFile = "  -i\t<PE  文件>\t\t\t\t#列出Exe的导入表";
            strings.scanDir = "  -p\t<文件目录>\t\t\t\t#自动扫描指定目录下可疑的恶意程序";
            strings.signatureCheck = "  -s\t<签名校验>\t\t\t\t#只扫描有签名的exe程序";
            strings.excludeSystem = "  -e\t<排除 EXE>\t\t\t\t#排除系统系统dll和exe";
            strings.analyzeModule = "  -d\t<指定模块>\t\t\t\t#分析dll模块";
            strings.specifyArch = "  -x\t<指定架构>\t\t\t\t#指定要扫描的架构（x86/x64）";
            strings.excludeList = "  -g\t<排除列表>\t\t\t\t#排除指定dll的扫描";
            strings.viewImports = "  -IM\t<PE  文件>\t\t\t\t#查看导入表";
            strings.viewExports = "  -EX\t<PE  文件>\t\t\t\t#查看导出表";
            strings.excludeConsole = "  -nc\t<排除控制台>\t\t\t\t#排除控制台应用程序";
            strings.examples = "示例:";
            strings.showImports = "  ZeroEye.exe -i a.exe\t\t\t\t\t   #显示exe导入表";
            strings.scanDirExe = "  ZeroEye.exe -p c:\\\t\t\t\t\t   #扫描c盘下的exe";
            strings.analyzeDll = "  ZeroEye.exe -d a.dll\t\t\t\t\t   #分析指定dll的导入模块";
            strings.viewImportsExports = "  ZeroEye.exe -IM/-EX a.exe/a.dll\t\t\t   #查看导入表/导出表";
            strings.scanWithOptions = "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\"\t    #扫描c盘下的exe,并且只扫描64位有签名的程序";
            strings.scanWithExclude = "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\" -e   #同上，扫描仅需要系统dll的exe";
            strings.scanWithExcludeNoConsole = "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\" -nc  #同上，排除控制台应用程序";
            strings.programType = "程序类型: ";
            strings.consoleApp = "控制台应用程序";
            strings.guiApp = "图形界面应用程序";
            strings.importedDlls = "导入的DLL:";
            strings.noImportsFound = "未找到导入的DLL";
            strings.errorFile = "文件错误";
            strings.executionTime = "执行时间: ";
            strings.minutes = "分";
            strings.seconds = "秒";
            strings.Owner = "公众号：零攻防";
        }
        return strings;
    }

private:
    static bool IsEnglishSystem() {
        LANGID langId = GetUserDefaultUILanguage();
        return !(langId == 0x0804 || langId == 0x0404 || langId == 0x0C04);
    }
}; 