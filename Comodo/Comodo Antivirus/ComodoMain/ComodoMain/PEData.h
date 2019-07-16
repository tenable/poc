// David Wells
// @riscybusiness

#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <Windows.h>

struct SectionInfo {
	SectionInfo(char name[], bool isExecutable, int ro, int vo, int rs, int vs) {
		RtlCopyMemory(sectionName, name, strlen((char*)name));
		this->isExecutable = isExecutable;
		_rOffset = ro;
		_vOffset = vo;
		_rSize = rs;
		_vSize = vs;
	}
	char sectionName[8] = {};
	size_t _rOffset, _vOffset, _rSize, _vSize;
	bool isExecutable;
};

struct Thunk {
	std::string libname;
	DWORD firstThunk;
	std::vector<std::string> functionNames;
};

struct IAT {
	unsigned int offset;
	std::vector<Thunk> thunks;
};


class PEData
{
public:
	PEData(IMAGE_DOS_HEADER* exe);
	void* GetExeBuffer();
	PEData(std::wstring filePath);
	void Init(IMAGE_DOS_HEADER* exe);
	IAT GetIAT() { return iat; }
	std::vector<SectionInfo> GetSections() { return si; }
	IMAGE_OPTIONAL_HEADER *GetOptionalHeader() { return this->I_optionalHeader; }
	void *GetModuleBase() { return exe; }
	INT64 GetImageBase() { return (INT64)this->I_optionalHeader->ImageBase; }
	size_t GetExeSize() { return this->I_optionalHeader->SizeOfImage; }
	DWORD PEData::GetEntryPoint() { return this->I_optionalHeader->AddressOfEntryPoint; }
	~PEData();
	IMAGE_OPTIONAL_HEADER *I_optionalHeader;
private:
	IMAGE_NT_HEADERS *I_ntHeader;
	IMAGE_FILE_HEADER *I_fileHeader;
	IMAGE_DATA_DIRECTORY *I_dataDirectory;
	DWORD* Rva2Offset(DWORD dwRva);
	void ExtractSections();
	void ExtractImports();
	std::vector<SectionInfo> si;
	IAT iat;
	void* exe;
};