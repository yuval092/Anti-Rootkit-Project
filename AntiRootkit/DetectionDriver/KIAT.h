#ifndef __KIAT_H__
#define __KIAT_H__

#include "Common.h"

NTSTATUS ScanKIAT();
NTSTATUS ScanModuleIAT(
	PCHAR Name,
	ULONG BaseAddress,
	PNodeKIAT ModuleNode
);
NTSTATUS AddNewKernelModule(
	PCHAR ModuleName,
	ULONG ModuleBase
);
NTSTATUS AddModuleToList(
	PNodeKIAT NewNode
);
NTSTATUS RemoveModuleFromList(
	PCHAR Name
);
BOOLEAN IsModuleInLinkedList(
	PCHAR Name
);
NTSTATUS WriteKernelIatScanResults(
	HANDLE Handle
);
NTSTATUS InitVarsKIAT();
NTSTATUS UnloadKIAT();

#endif