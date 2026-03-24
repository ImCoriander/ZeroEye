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
    std::string scanType;
    std::string viewImports;
    std::string viewExports;
    std::string examples;
    std::string showImports;
    std::string showImportsDotNet;
    std::string scanDirExe;
    std::string analyzeDll;
    std::string analyzeDotNetExe;
    std::string scanTypeExamples;
    std::string viewImportsExports;
    std::string scanWithOptions;
    std::string scanWithExclude;
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
            strings.help =             "  -h   <help|examples>              Display help information";
            strings.inputFile =        "  -i   <PE file>                    Analyze PE file (auto-detect native/.NET)";
            strings.scanDir =          "  -p   <directory>                  Scan suspicious programs in specified directory";
            strings.signatureCheck =   "  -s   <signature check>            Only scan signed exe programs";
            strings.excludeSystem =    "  -e   <exclude EXE>                Exclude system dlls and exes";
            strings.analyzeModule =    "  -d   <PE module>                  Generate hijack templates (auto-detect native/.NET)";
            strings.specifyArch =      "  -x   <specified architecture>     Specify architecture to scan (x86/x64)";
            strings.excludeList =      "  -g   <exclude list>               Exclude specified dlls from scanning";
            strings.scanType =         "  -t   <type>                       Scan type: gui,cmd,exe,dotnet,sys,all (default: all)";
            strings.viewImports =      "  -IM  <PE file>                    View import table";
            strings.viewExports =      "  -EX  <PE file>                    View export table";
            strings.examples = "\nexamples:";
            strings.showImports =             "  ZeroEye.exe -i a.exe                                          Show exe imports (native PE)";
            strings.showImportsDotNet =       "  ZeroEye.exe -i app.exe                                        Analyze .NET hijack vectors";
            strings.scanDirExe =              "  ZeroEye.exe -p c:\\                                            Scan all types in c drive";
            strings.analyzeDll =              "  ZeroEye.exe -d a.dll                                          Generate proxy DLL templates";
            strings.analyzeDotNetExe =        "  ZeroEye.exe -d app.exe                                        Generate .NET hijack config";
            strings.scanTypeExamples =        "  ZeroEye.exe -p c:\\ -t gui                                    Scan only GUI programs\n"
                                              "  ZeroEye.exe -p c:\\ -t dotnet                                  Scan only .NET programs\n"
                                              "  ZeroEye.exe -p c:\\ -t sys                                     Scan only kernel drivers\n"
                                              "  ZeroEye.exe -p c:\\ -t gui,dotnet                              Scan GUI + .NET programs";
            strings.viewImportsExports =      "  ZeroEye.exe -IM/-EX a.exe/a.dll                              View imports/exports";
            strings.scanWithOptions =         "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\"        Scan signed 64-bit programs";
            strings.scanWithExclude =         "  ZeroEye.exe -p c:\\ -s -x 64 -g \"...\" -e                     Only exe requiring system dlls";
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
            // 中文
            strings.usage = "用法: ZeroEye [选项]";
            strings.options = "选项:";
            strings.help =             "  -h   <帮助|示例>                  显示帮助信息";
            strings.inputFile =        "  -i   <PE 文件>                    分析PE文件 (自动识别 原生/.NET)";
            strings.scanDir =          "  -p   <目录>                       扫描指定目录下的可疑程序";
            strings.signatureCheck =   "  -s   <签名检查>                   仅扫描有数字签名的程序";
            strings.excludeSystem =    "  -e   <排除EXE>                    排除仅依赖系统DLL的程序";
            strings.analyzeModule =    "  -d   <PE 模块>                    生成劫持模板 (自动识别 原生/.NET)";
            strings.specifyArch =      "  -x   <架构>                       指定扫描架构 (64/86)";
            strings.excludeList =      "  -g   <排除列表>                   排除指定DLL (用|分隔)";
            strings.scanType =         "  -t   <类型>                       扫描类型: gui,cmd,exe,dotnet,sys,all (默认: all)";
            strings.viewImports =      "  -IM  <PE 文件>                    查看导入表";
            strings.viewExports =      "  -EX  <PE 文件>                    查看导出表";
            strings.examples = "\n示例:";
            strings.showImports =             "  ZeroEye.exe -i a.exe                                          查看exe导入DLL (原生PE)";
            strings.showImportsDotNet =       "  ZeroEye.exe -i app.exe                                        分析.NET劫持向量";
            strings.scanDirExe =              "  ZeroEye.exe -p c:\\                                            扫描C盘所有类型";
            strings.analyzeDll =              "  ZeroEye.exe -d a.dll                                          生成代理DLL模板";
            strings.analyzeDotNetExe =        "  ZeroEye.exe -d app.exe                                        生成.NET劫持配置";
            strings.scanTypeExamples =        "  ZeroEye.exe -p c:\\ -t gui                                    仅扫描GUI程序\n"
                                              "  ZeroEye.exe -p c:\\ -t dotnet                                  仅扫描.NET程序\n"
                                              "  ZeroEye.exe -p c:\\ -t sys                                     仅扫描内核驱动\n"
                                              "  ZeroEye.exe -p c:\\ -t gui,dotnet                              扫描GUI + .NET程序";
            strings.viewImportsExports =      "  ZeroEye.exe -IM/-EX a.exe/a.dll                              查看导入/导出表";
            strings.scanWithOptions =         "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\"        扫描已签名的64位程序";
            strings.scanWithExclude =         "  ZeroEye.exe -p c:\\ -s -x 64 -g \"...\" -e                     仅保留依赖系统DLL的程序";
            strings.programType = "程序类型: ";
            strings.consoleApp = "控制台应用程序";
            strings.guiApp = "图形界面应用程序";
            strings.importedDlls = "导入的DLL:";
            strings.noImportsFound = "未找到导入的DLL";
            strings.errorFile = "文件错误";
            strings.executionTime = "执行时间: ";
            strings.minutes = "分";
            strings.seconds = "秒";
            strings.Owner = "公众号: 零攻防";
        }
        return strings;
    }

private:
    static bool IsEnglishSystem() {
        LANGID langId = GetUserDefaultUILanguage();
        return !(langId == 0x0804 || langId == 0x0404 || langId == 0x0C04);
    }
};
