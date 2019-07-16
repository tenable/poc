#pragma once
#include <Windows.h>
#include <string>

struct messageBlock {
	DWORD header;
	ULONG ioctl;
	ULONG unkwn2;
	ULONG unkwn3; 
	ULONG unkwn4;
	ULONG unkwn5;
	DWORD pid;
	DWORD unkwn6;
	DWORD unkwn7;
	BYTE buff[0x1024];
};


class CmdGuardInterface
{
	HANDLE hAuthPort;
	std::wstring portName;
public:
	CmdGuardInterface(std::wstring portName);
	HRESULT SendAuthMessage(messageBlock* msg);
	~CmdGuardInterface();
};

