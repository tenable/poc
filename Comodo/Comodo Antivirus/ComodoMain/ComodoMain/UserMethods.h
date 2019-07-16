#pragma once
#include <Windows.h>
#include <iostream>
#include "CisCOM.h"
#include <locale>
#include <string>
#include "CmdGuardInterface.h"
#include "Hollower.h"
#include <fltUser.h>
#include <Shlwapi.h>
#include <tlhelp32.h>
#include <wbemcli.h>

class UserMethods
{
private:
	void RepairNtDll();
	void RtlInitUnicodeString(PUNICODE_STRING u, wchar_t* string);
	void ChangePEBImageName(std::wstring str);
public:
	UserMethods();
	~UserMethods(); 
	void SandboxEscape();
	void RegSZWrite(HKEY hive, std::wstring regPath, std::wstring regKey, std::wstring regValue, std::wstring data);
	void ClobberCavSignature(std::wstring wstr, bool flagAll);
	void ReplaceCmdAgentService(std::wstring imagePath);
	void CrashServicePort();
	void CrashCmdAgent();
	void SandboxProcess(DWORD PID);
	void CrashCmdVirth();
	void CrashCmdGuiPort();
};
