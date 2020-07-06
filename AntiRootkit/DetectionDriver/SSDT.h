#ifndef __SSDT_H__
#define __SSDT_H__

#include "Common.h"

// ----------------------------------------------------------------------------------------------
// Functions

NTSTATUS WriteSsdtScanResults(HANDLE Handle);
NTSTATUS InitVarsSSDT();
NTSTATUS UnloadSSDT();
NTSTATUS ScanSSDT();


// ----------------------------------------------------------------------------------------------
// Defines and imports

typedef struct SystemServiceDescriptorTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}SSDT, *PSSDT;

NTKERNELAPI PSSDT KeServiceDescriptorTable;

#endif
