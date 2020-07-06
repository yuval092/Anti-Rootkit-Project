#include "Common.h"


// Global Variables
ULONG NtoskrnlBase = 0, NtoskrnlSize = 0;


/*
	Initalize the NtoskrnlBase and NtoskrnlSize vars.
	Called on driver entry.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS InitNtoskrnlVars()
{
	PAUX_MODULE_EXTENDED_INFO pData;
	ULONG BuffLen = 0;
	NTSTATUS Status;

	// Required before AuxKlibQueryModuleInformation
	AuxKlibInitialize();

	// Get the length returned from the operation
	Status = AuxKlibQueryModuleInformation(&BuffLen, sizeof(AUX_MODULE_EXTENDED_INFO), 0);
	if (!NT_SUCCESS(Status) || BuffLen == 0)
	{
		DbgPrint("[-] Failed to get ntoskrnl address range \r\n");
		return Status;
	}

	// Allocate space for the data to be collected
	pData = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(PagedPool, BuffLen, 'tag');
	RtlZeroMemory(pData, BuffLen);

	// Now get data and save it in pData
	Status = AuxKlibQueryModuleInformation(&BuffLen, sizeof(AUX_MODULE_EXTENDED_INFO), pData);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to get ntoskrnl address range \r\n");
		ExFreePoolWithTag(pData, 'tag');
		return Status;
	}

	NtoskrnlBase = (ULONG)pData->BasicInfo.ImageBase;
	NtoskrnlSize = pData->ImageSize;

	ExFreePoolWithTag(pData, 'tag');
	return Status;
}


/*
	Get a list of all kernel modules currently loaded
	and information about them such as their base address.
	Input: None.
	Output: The module list.
*/
ModuleData GetKernelModuleList()
{
	PAUX_MODULE_EXTENDED_INFO pData;
	ULONG BuffLen = 0;
	ModuleData Module;
	NTSTATUS Status;

	// Zero memory
	Module.Data = NULL;
	Module.Length= 0;

	// Required before AuxKlibQueryModuleInformation
	AuxKlibInitialize();

	// Get the length returned from the operation
	Status = AuxKlibQueryModuleInformation(&BuffLen, sizeof(AUX_MODULE_EXTENDED_INFO), 0);
	if (!NT_SUCCESS(Status) || BuffLen == 0)
	{
		DbgPrint("[-] Failed to get module list \r\n");
		goto end;
	}

	// Allocate space for the data to be collected
	pData = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePool(PagedPool, BuffLen);
	RtlZeroMemory(pData, BuffLen);

	// Now get data and save it in pData
	Status = AuxKlibQueryModuleInformation(&BuffLen, sizeof(AUX_MODULE_EXTENDED_INFO), pData);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to get module list \r\n");
		ExFreePool(pData);
		goto end;
	}

	Module.Data = pData;
	Module.Length = BuffLen / sizeof(AUX_MODULE_EXTENDED_INFO);

end:
	return Module;
}


// Ntoskrnl base address getter
ULONG GetNtoskrnlBase()
{
	return NtoskrnlBase;
}


// Ntoskrnl image size getter
ULONG GetNtoskrnlSize()
{
	return NtoskrnlSize;
}