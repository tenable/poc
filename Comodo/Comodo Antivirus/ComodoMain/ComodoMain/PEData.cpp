// David Wells
// @riscybusiness

#include "stdafx.h"
#include "PEData.h"
#include <algorithm>
#include "NtStuff.h"

PEData::PEData(IMAGE_DOS_HEADER *exe)
{
	Init(exe);
}

PEData::PEData(std::wstring filePath)
{
	HANDLE hPE = CreateFile(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (hPE == INVALID_HANDLE_VALUE)
		exit(-1);
	LARGE_INTEGER fileSize = { 0,0 };
	GetFileSizeEx(hPE, &fileSize);
	IMAGE_DOS_HEADER *hollowedImage = (IMAGE_DOS_HEADER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize.LowPart);
	DWORD written;
	ReadFile(hPE, (void*)hollowedImage, fileSize.LowPart, &written, NULL);
	CloseHandle(hPE);

	Init(hollowedImage);
}

void PEData::Init(IMAGE_DOS_HEADER *exe)
{
	this->exe = (void*)exe;
	this->I_ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>((BYTE*)exe + ((IMAGE_DOS_HEADER*)exe)->e_lfanew);
	this->I_fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(&I_ntHeader->FileHeader);
	this->I_optionalHeader = reinterpret_cast<IMAGE_OPTIONAL_HEADER*>(&this->I_ntHeader->OptionalHeader);
	ExtractSections();
	ExtractImports();
}

void* PEData::GetExeBuffer()
{
	return this->exe;
}

DWORD* PEData::Rva2Offset(DWORD dwRva)
{
	IMAGE_SECTION_HEADER *secHeader = IMAGE_FIRST_SECTION(this->I_ntHeader);

	for (USHORT i = 0; i < this->I_fileHeader->NumberOfSections; i++)
	{
		if (dwRva >= secHeader->VirtualAddress)
		{
			if (dwRva < secHeader->VirtualAddress + secHeader->Misc.VirtualSize)
				return (DWORD*)(dwRva - secHeader->VirtualAddress + secHeader->PointerToRawData);
		}
		secHeader++;
	}
	return NULL;
}

void PEData::ExtractSections()
{
	IMAGE_SECTION_HEADER *secHeader = IMAGE_FIRST_SECTION(this->I_ntHeader);
	bool isExecutable;
	for (int i = 0; i < this->I_fileHeader->NumberOfSections; i++)
	{
		isExecutable = secHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE;
		si.push_back(SectionInfo((char*)secHeader->Name, isExecutable, secHeader->PointerToRawData, secHeader->VirtualAddress, secHeader->SizeOfRawData, secHeader->Misc.VirtualSize));

		secHeader++;
	}

}

//sort function ordering by OFT
bool sortOFT(IMAGE_IMPORT_DESCRIPTOR* a, IMAGE_IMPORT_DESCRIPTOR* b)
{
	if (a->OriginalFirstThunk > b->OriginalFirstThunk)
		return false;
	return true;

}

void PEData::ExtractImports()
{

	IMAGE_IMPORT_DESCRIPTOR *imports = (IMAGE_IMPORT_DESCRIPTOR*)((INT64)exe + (INT64)Rva2Offset(this->I_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

	std::vector<IMAGE_IMPORT_DESCRIPTOR*> thunkList;
	//Do not convert to raw address, we need loaded location
	this->iat.offset = this->I_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	int importSize = (this->I_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	//build in order import (needed for IAT)

	while (imports->Name != NULL)
	{
		thunkList.push_back(imports);
		imports++;
	}

	std::sort(thunkList.begin(), thunkList.end(), sortOFT);

	for (std::vector<IMAGE_IMPORT_DESCRIPTOR*>::iterator it = thunkList.begin(); it != thunkList.end(); ++it)
	{
		Thunk t;

		t.libname = std::string((char*)((INT64)exe + (INT64)Rva2Offset((*it)->Name)));
		t.firstThunk = (*it)->FirstThunk;
		IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((INT64)exe + (INT64)Rva2Offset((*it)->OriginalFirstThunk));

		while (*(DWORD*)thunk != NULL) {

			t.functionNames.push_back((char*)((INT64)exe + (INT64)Rva2Offset(thunk->u1.Function + 2)));
			thunk++;
		}
		this->iat.thunks.push_back(t);
	}
}

PEData::~PEData()
{
}
