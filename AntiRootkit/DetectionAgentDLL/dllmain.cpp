// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// Globals 
std::vector<DWORD> driverKnownPids;
HANDLE hDriver = NULL;

using std::string;
using std::vector;
using std::pair;


BOOL APIENTRY DllMain( 
	HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
		break;
    }
    return TRUE;
}


extern "C"
{
	/*
		Start the agent and initialize its variables.
		Input: None.
		Output: If successful - True, otherwise false.
	*/
	__declspec(dllexport) BOOL StartAgent()
	{
		try
		{
			// Register driver (write it to the registery)
			system(DRIVER_REGISTER);

			// Load driver to the kernel and start its service
			system(DRIVER_START);
		}
		catch (...)
		{
			return FALSE;
		}

		hDriver = CreateFileA(
			DRIVER_SYMBOL_NAME,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
			NULL
		);
		if (hDriver == INVALID_HANDLE_VALUE)
		{
			printf("[-] Failed to get device handle\n");
			return FALSE;
		}

		return TRUE;
	}


	/*
		Stop the agent and the driver.
		Input: None.
		Output: If successful - True, otherwise false.
	*/
	__declspec(dllexport) BOOL StopAgent()
	{
		try
		{
			if (hDriver != NULL && hDriver != INVALID_HANDLE_VALUE)
				CloseHandle(hDriver);
		}
		catch (...) 
		{ 
			return FALSE;
		}

		return TRUE;
	}


	/*
		Send a add new process request to the driver using ioctl.
		Input: The pid of the new process to be added.
		Output: If successful - True, otherwise false.
	*/
	__declspec(dllexport) BOOL SendNewProcessToDriver(DWORD Pid)
	{
		DWORD junk;

		DWORD result = DeviceIoControl(
			hDriver,
			IOCTL_ADD_NEW_PROCESS,
			&Pid,
			sizeof(Pid),
			NULL,
			NULL,
			&junk,
			NULL
		);
		if (result == FALSE)
		{
			std::cout << "[-] Failed to send add_new_process ioctl to driver" << std::endl;
			return FALSE;
		}

		return TRUE;
	}


	/*
		Get the current process list of the os.
		Input: a DWORD array to be filled with PIDs.
		Output: The length of the recieved process list.
	*/
	__declspec(dllexport) BOOL UpdateDriverProcessList()
	{
		DWORD processList[LIST_SIZE];
		DWORD cbNedded, count;


		try
		{
			if (!EnumProcesses(processList, sizeof(DWORD) * LIST_SIZE, &cbNedded))
			{
				std::cout << "[-] Failed to get process list" << std::endl;
				return FALSE;
			}

			// Convert array to vector in order to use c++ 11 features
			std::vector<DWORD> processListVec(processList, processList + (cbNedded / sizeof(DWORD)));

			// Iterate all processes in the os
			// and search for new processes
			for (auto proc : processListVec)
			{
				count = std::count(driverKnownPids.begin(), driverKnownPids.end(), proc);
				if (count > 1)
				{
					std::cout << "[-] Duplicate process: " << proc << std::endl;
				}
				else if (count == 0)	// new process to be scanned
				{
					if (SendNewProcessToDriver(proc))
						driverKnownPids.push_back(proc);
				}
			}

			// Iterate all processes in driver's list
			// and search for deleted processes
			vector<DWORD>::iterator it = driverKnownPids.begin();
			while (it != driverKnownPids.end())
			{
				count = std::count(processListVec.begin(), processListVec.end(), *it);
				if (count == 0)
					it = driverKnownPids.erase(it);
				else
					++it;
			}
		}
		catch (...)
		{
			return FALSE;
		}

		return TRUE;
	}


	/*
		Send a scan request to the driver using ioctl.
		Input: None.
		Output: If successful - True, otherwise false.
	*/
	__declspec(dllexport) BOOL SendScanRequestToDriver()
	{
		DWORD junk;

		DWORD result = DeviceIoControl(
			hDriver,
			IOCTL_SCAN_HOOKS,
			NULL,
			NULL,
			NULL,
			NULL,
			&junk,
			NULL
		);
		if (result == FALSE)
		{
			std::cout << "[-] Failed to send add_new_process ioctl to driver" << std::endl;
			return FALSE;
		}

		return TRUE;
	}
}