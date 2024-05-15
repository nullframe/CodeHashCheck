#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <TlHelp32.h>


DWORD GetProcessIdByName(const wchar_t* processName) {

    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(processEntry);
        if (Process32First(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }

    return processId;
}

uintptr_t GetModuleBaseAddress(HANDLE hProcess, const wchar_t* moduleName) {

    HMODULE modules[1024];
    DWORD needed;

    if (!EnumProcessModulesEx(hProcess, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
        CloseHandle(hProcess);
        return 0;
    }

    int moduleCount = needed / sizeof(HMODULE);

    uintptr_t baseAddress = 0;
    for (int i = 0; i < moduleCount; ++i) {
        wchar_t moduleNameBuffer[MAX_PATH];
        if (GetModuleBaseName(hProcess, modules[i], moduleNameBuffer, sizeof(moduleNameBuffer) / sizeof(wchar_t))) {
            if (wcscmp(moduleNameBuffer, moduleName) == 0) {
                MODULEINFO moduleInfo;
                if (GetModuleInformation(hProcess, modules[i], &moduleInfo, sizeof(moduleInfo))) {
                    baseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
                    break;
                }
            }
        }
    }

    return baseAddress;
}

unsigned int bytesToInt(const unsigned char* bytes, size_t size) {

    unsigned int result = 0;

    for (size_t i = 0; i < size; ++i) {
        result |= bytes[i] << (8 * i);
    }

    return result;
}

uintptr_t GetPEHeaderAddress(HANDLE hProcess, uintptr_t baseAddr) {

    const size_t size = 4;
    unsigned char buffer[size];

    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddr + 0x3c), &buffer, size, NULL)) {
        return 0;
    }

    return baseAddr + bytesToInt(buffer, size);
}

size_t GetOptionalHeaderSize(HANDLE hProcess, uintptr_t peHeaderAddress) {

    const size_t size = 2;
    unsigned char buffer[size];

    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(peHeaderAddress + 0x14), &buffer, size, NULL)) {
        return 0;
    }

    return bytesToInt(buffer, size);
}

size_t GetTextSectionSize(HANDLE hProcess, uintptr_t sectionHeaderAddr) {

    const size_t size = 4;
    unsigned char buffer[size];

    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(sectionHeaderAddr + 0x8), &buffer, size, NULL)) {
        return 0;
    }

    return bytesToInt(buffer, size);
}

uintptr_t GetTextSectionAddress(HANDLE hProcess, uintptr_t baseAddr, uintptr_t sectionHeaderAddr) {

    const size_t size = 4;
    unsigned char buffer[size];

    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(sectionHeaderAddr + 0xc), &buffer, size, NULL)) {
        return 0;
    }

    return baseAddr + bytesToInt(buffer, size);
}

unsigned int YourHashFunction(const BYTE* buffer, size_t size) {

    unsigned int hash = 0;

    for (size_t i = 0; i < size; ++i) {
        hash += buffer[i];
    }

    return hash;
}

bool readTextSection(HANDLE hProcess, uintptr_t textSectionAddr, size_t textSectionSize) {

    BYTE* buffer = new BYTE[textSectionSize];
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(textSectionAddr), buffer, textSectionSize, &bytesRead)) {
        return 0;
    }

    unsigned int hash = YourHashFunction(buffer, bytesRead);

    delete[] buffer;

    std::cout << "HASH: " << hash << std::endl;

    return 1;
}

int main() {

    wchar_t processName[] = L"processname.exe";
    std::wcout << "Process name: " << processName << std::endl;

    DWORD processId = GetProcessIdByName(processName);
    std::cout << "Process ID: " << processId << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return 1;
    }

    uintptr_t baseAddr = GetModuleBaseAddress(hProcess, processName);
    if (!baseAddr) {
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << std::hex;
    std::cout << "Base address: " << baseAddr << std::endl;

    uintptr_t peHeaderAddr = GetPEHeaderAddress(hProcess, baseAddr);
    if (!peHeaderAddr) {
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "PE Header address: " << peHeaderAddr << std::endl;

    size_t optionalHeaderSize = GetOptionalHeaderSize(hProcess, peHeaderAddr);
    if (!optionalHeaderSize) {
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "Optional Header size: " << optionalHeaderSize << std::endl;

    uintptr_t sectionHeaderAddr = peHeaderAddr + 0x18 + optionalHeaderSize;
    if (!sectionHeaderAddr) {
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "Section Header address: " << sectionHeaderAddr << std::endl;

    uintptr_t textSectionAddr = GetTextSectionAddress(hProcess, baseAddr, sectionHeaderAddr);
    if (!textSectionAddr) {
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "Text Section address: " << textSectionAddr << std::endl;

    size_t textSectionSize = GetTextSectionSize(hProcess, sectionHeaderAddr);
    if (!textSectionSize) {
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "Text Section size: " << textSectionSize << std::endl;

    if (!readTextSection(hProcess, textSectionAddr, textSectionSize)) {
        CloseHandle(hProcess);
        return 1;
    }

    CloseHandle(hProcess);

    system("pause");

    return 0;
}