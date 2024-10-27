#include <iostream>
#include <windows.h>
#include <winnt.h>
#include <vector>


std::vector<std::string> systemDLLs;
std::vector<std::string> userDLLs;



bool Is_SystemDLL(const char* dllName) {

    HMODULE hModule = LoadLibraryA(dllName);
    if (hModule)
    {
        FreeLibrary(hModule);
        return true;
    }
    return false;

}
void ViewImportedDLLs(const char* filePath) {
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

    std::cout << "Imported DLLs:" << std::endl;
    while (importDescriptor->Name != NULL) {
        const char* dllName = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(hModule) + importDescriptor->Name);

        if (Is_SystemDLL(dllName))
        {
            systemDLLs.push_back(dllName);
        }
        else
        {
            userDLLs.push_back(dllName);
        }
        importDescriptor++;
    }

    for (const auto& dll : systemDLLs) {
        std::cout << "System DLL Name: " << dll << std::endl;
    }
    for (const auto& dll : userDLLs) {
        std::cout << "User DLL Name: " << dll << std::endl;
    }
    FreeLibrary(hModule);
}

bool endsWithExe(const char* str) {
    size_t length = strlen(str);
    if (length < 4) { // ".exe" 至少有4个字符
        return false;
    }
    return strcmp(str + length - 4, ".exe") == 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2 || !endsWithExe(argv[1])) {
        std::cout << "Usage:" << argv[0] << " <exe_file_path>" << std::endl;
        return 1;
    }
    else
    {
        ViewImportedDLLs(argv[1]); 
    }

    


    
    return 0;
}
