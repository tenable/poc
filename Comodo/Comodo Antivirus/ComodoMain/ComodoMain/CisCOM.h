#pragma once
#include "NtStuff.h"

class CisClientInfo {
public:
	CisClientInfo() { pid = GetCurrentProcessId(); }
	wchar_t* DomainName;
	wchar_t* UserName;
	wchar_t* Context; // CavShellExtention
	wchar_t* ClientImagePath;
	wchar_t* ComputerName;
	DWORD v1 = 1;
	DWORD pid;
	DWORD v2 = 0;
	DWORD v3 = 1;
};

class SvcRegKey {
public:
	virtual void QueryInterface() = 0;
	virtual void AddRef() = 0;
	virtual void Release() = 0;
	virtual void proc3() = 0;
	virtual void proc4() = 0;
	virtual void proc5() = 0;
	virtual void proc6() = 0;
	virtual void ReadRegValue(BSTR valueName, BSTR* data) = 0;
	virtual void SetRegSz(BSTR valueName, BSTR data) = 0;
	virtual void proc7() = 0;
	virtual void proc8() = 0;
	virtual void proc9() = 0;
	virtual void proc10() = 0;
	virtual void proc11() = 0;
	virtual void OpenWriteKey(BSTR subkey, DWORD val, void** regInterface) = 0;
	virtual void proc13() = 0;
	virtual void proc14() = 0;
	virtual void OpenNewKey(HKEY hkey, BSTR subkey, bool permission, DWORD permission2) = 0;
};

class ISvcRegistryAccess {
public:
	virtual void QueryInterface() = 0;
	virtual void AddRef() = 0;
	virtual void Release() = 0;
	virtual void proc3() = 0;
	virtual void proc4() = 0;
	virtual void proc5() = 0;
	virtual void GetRegInterface(HKEY hKey, BSTR regPath, void** regInterface) = 0;
};

class CisClassFactory {
public:
	virtual void QueryInterface() = 0;
	virtual void AddRef() =0;
	virtual void Release() =0;
	virtual void proc3() = 0;
	virtual void proc4() =0;
	virtual HRESULT CreateInstance(void* cb, bool zero, const IID& facade, LPVOID* out) =0;
	virtual void proc6() =0;
};

class IServiceProv {
public:
	virtual void QueryInterface(const IID& iid, LPVOID* ppv_out) = 0;
	virtual void AddRef() = 0;
	virtual void Release() = 0;
	virtual void GetIReg(IID empty, IID svcRegAccess, LPVOID* out) = 0;
	virtual void proc4() = 0;
	virtual HRESULT GetCisGate(void* cb, bool zero, const IID& facade, LPVOID* out) = 0;
	virtual void proc6() = 0;
};

class CisGate {
public:
	virtual HRESULT QueryInterface(const IID& iid, LPVOID* ppv_out) = 0;
	virtual void AddRef() =0;
	virtual void Release() =0;
	virtual HRESULT RegClientInfo(int val, CisClientInfo* info) = 0;
	virtual void proc4() =0;
	virtual void proc5() =0;
	virtual void proc6() =0;
	virtual void proc7() =0;
	virtual void proc8() =0;
	virtual void proc9() =0;
	virtual void proc10() =0;
	virtual void proc11() =0;
	virtual void proc12() =0;
	virtual void proc13() =0;
	virtual void proc14() =0;
	virtual void proc15() =0;
	virtual void proc16() =0;
	virtual void proc17() =0;
	virtual void proc18() =0;
	virtual void proc19() =0;
	virtual void proc20() =0;
	virtual void proc21() =0;
	virtual HRESULT ScanFile(int _one, wchar_t** cisFile, bool _false, INT64 y, void** out, INT64 v) =0;
	virtual void proc23() =0;
	virtual void proc24() =0;
	virtual void proc25() =0;
	virtual void proc26() =0;
	virtual void proc27() =0;
	virtual void proc28() =0;
	virtual void proc29() =0;
	virtual void proc30() =0;
	virtual void proc31() =0;
	virtual void proc32() =0;
	virtual void proc33() =0;
	virtual void proc34() =0;
	virtual void proc35() =0;
	virtual void proc36() =0;
	virtual void proc37() =0;
	virtual void proc38() =0;
	virtual void proc39() =0;
	virtual void proc40() =0;
	virtual void proc41() =0;
	virtual void proc42() =0;
	virtual void proc43() =0;
	virtual void proc44() =0;
	virtual void proc45() =0;
	virtual void proc46() =0;
	virtual void proc47() =0;
	virtual void proc48() =0;
	virtual void proc49() =0;
	virtual void proc50() =0;
	virtual void proc51() =0;
	virtual void proc52() =0;
	virtual void proc53() =0;
	virtual void proc54() =0;
	virtual void proc55() =0;
	virtual void proc56() =0;
	virtual void proc57() =0;
	virtual void proc58() =0;
};