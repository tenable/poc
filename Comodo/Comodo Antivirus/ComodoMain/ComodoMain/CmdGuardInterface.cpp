#include "stdafx.h"
#include "CmdGuardInterface.h"
#include <fltUser.h>

CmdGuardInterface::CmdGuardInterface(std::wstring portName)
{
	BYTE out[0x1000];
	HRESULT res = FilterConnectCommunicationPort(portName.c_str(), NULL, NULL, NULL, NULL, &hAuthPort);
}

HRESULT CmdGuardInterface::SendAuthMessage(messageBlock* msg) {

	BYTE out[0x1000];
	DWORD returned;
	if (hAuthPort != INVALID_HANDLE_VALUE)
		FilterSendMessage(hAuthPort, msg, 0x1024, out, 0x734, &returned);
	return 0;
}

CmdGuardInterface::~CmdGuardInterface()
{
}

