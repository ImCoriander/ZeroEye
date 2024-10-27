#include <iostream>
#include <windows.h>
#include <vector>
#include <io.h>
#include <filesystem>
#include <fstream>
bool isx64 = false;
bool Is_SystemDLL(const char* dllName) {

    HMODULE hModule = LoadLibraryA(dllName);
    if (hModule)
    {
        FreeLibrary(hModule);
        return true;
    }
    return false;

}

void SetConsoleColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}
void Exe_ViewImportedDLLs(const char* filePath) {
    HMODULE hModule = LoadLibraryExA(filePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule == NULL) {
        std::cerr << "Failed to load the PE file." << std::endl;
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature." << std::endl;
        FreeLibrary(hModule);
        return;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid NT signature." << std::endl;
        FreeLibrary(hModule);
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<BYTE*>(hModule) +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (importDescriptor == NULL) {
        std::cerr << "No import table found." << std::endl;
        FreeLibrary(hModule);
        return;
    }

    std::vector<std::string> DllList;
    std::cout << "Imported DLLs:" << std::endl;
    while (importDescriptor->Name != NULL) {
        const char* dllName = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(hModule) + importDescriptor->Name);

        DllList.push_back(dllName);
        importDescriptor++;
    }

    for (const auto& dll : DllList) {
        if (!Is_SystemDLL(dll.c_str()))
        {
            std::cout << "[+] " << dll << std::endl;
        }
        else
        {
            std::cout << "   " << dll << std::endl;
        }
        
    }

    FreeLibrary(hModule);
}

void File_ViewImportedDLLs(const char* filePath, const char* ExeName) {
    HMODULE hModule = LoadLibraryExA(filePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule == NULL) {
        std::cout << filePath << std::endl;
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << filePath << std::endl;
        FreeLibrary(hModule);
        return;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << filePath << std::endl;
        FreeLibrary(hModule);
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<BYTE*>(hModule) +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (importDescriptor == NULL) {
        FreeLibrary(hModule);
        return;
    }

    std::vector<std::string> DllList;
    while (importDescriptor->Name != NULL) {
        const char* dllName = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(hModule) + importDescriptor->Name);

        DllList.push_back(dllName);
        importDescriptor++;
    }
    int iNum = 0;
    for (const auto& dll : DllList) {
        if (!Is_SystemDLL(dll.c_str()))
        {
            iNum += 1;
        }

    }
    if (!iNum)
    {
        std::cout  << filePath << std::endl;
        return;
    }
    else
    {
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "[+] " << filePath << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    // 获取当前进程路径
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);
    std::filesystem::path currentDir = std::filesystem::path(currentPath).parent_path();
    std::filesystem::path targetDir;
    if (isx64)
    {
        targetDir = currentDir / "binX64" / ExeName;
    }
    else
    {
        targetDir = currentDir / "binX86" / ExeName;
    }
   

    // 创建目标文件夹
    if (!std::filesystem::exists(targetDir)) {
        std::filesystem::create_directories(targetDir);
    }
    std::filesystem::copy_file(filePath, targetDir / ExeName, std::filesystem::copy_options::overwrite_existing);
    // 移动DLL文件并记录名称
    std::ofstream dllNamesFile(targetDir / "Infos.txt");
    dllNamesFile << filePath << std::endl;
    std::filesystem::path sourceDir = std::filesystem::path(filePath).parent_path();
    for (const auto& dll : DllList) {
        std::filesystem::path sourceDllPath = sourceDir  / dll;
        std::filesystem::path targetDllPath = targetDir / dll;
        if (!Is_SystemDLL(dll.c_str()))
        {
            dllNamesFile << "[+] " << dll << std::endl;
        }
        else
        {
            dllNamesFile <<  dll << std::endl;
        }
        
        if (std::filesystem::exists(sourceDllPath)) {
            std::filesystem::copy_file(sourceDllPath, targetDllPath, std::filesystem::copy_options::overwrite_existing);
        }
    }

    dllNamesFile.close();
    FreeLibrary(hModule);
}
void getFiles(std::string path, std::vector<std::string>& files)
{
    //文件句柄
    intptr_t hFile = 0;
    //文件信息
    struct _finddata_t fileinfo;
    std::string p;
    if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1)
    {
        do
        {
            if ((fileinfo.attrib & _A_SUBDIR))
            {
                // 检查目录名是否以 $ 开头
                if (fileinfo.name[0] != '$')
                {
                    if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0)
                        getFiles(p.assign(path).append("\\").append(fileinfo.name), files);
                }
            }
            else
            {
                files.push_back(p.assign(path).append("\\").append(fileinfo.name));
                std::string IsExe = fileinfo.name;
                if (IsExe.substr(IsExe.size() - 4) == ".exe")
                {
                    
                    File_ViewImportedDLLs(files.back().c_str(), fileinfo.name);
                }
            }
        } while (_findnext(hFile, &fileinfo) == 0);
        _findclose(hFile);
    }
}

void DisplayHelp() {

    std::cout << "Usage: ZeroEye [options]" << std::endl;
    std::cout << "选项:" << std::endl;
    std::cout << "  -h\t帮助" << std::endl;
    std::cout << "  -i\t<Exe 路径>\t列出Exe的导入表" << std::endl;
    std::cout << "  -p\t<文件路径>\t自动搜索文件路径下可劫持利用的白名单" << std::endl;
}
int main(int argc, char* argv[]) {


#if defined(_WIN64)
    isx64 = true;
#else
    isx64 = false;
#endif
    std::cout << R"(
  _____                        _____                
 |__  /   ___   _ __    ___   | ____|  _   _    ___ 
   / /   / _ \ | '__|  / _ \  |  _|   | | | |  / _ \
  / /_  |  __/ | |    | (_) | | |___  | |_| | |  __/
 /____|  \___| |_|     \___/  |_____|  \__, |  \___|
                                       |___/                 
)" << std::endl;
    std::cout << (isx64 ? "\t\t\t\t  x64" : "\t\t\t\t  x86") << " Version:3.0\n" << std::endl;

    if (argc < 2) {
        DisplayHelp();
        return 1;
    }


    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0) {
            DisplayHelp();
            return 0;
        }
        else if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
 
                Exe_ViewImportedDLLs(argv[++i]);
            }
        }
        else if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                std::vector<std::string> vec_img_path;
                getFiles(argv[++i], vec_img_path);
            }
        }

        else {
            std::cerr << "Unknown option: " << argv[i] << std::endl;
            DisplayHelp();
            return 1;
        }
    }

    
    return 0;
}
