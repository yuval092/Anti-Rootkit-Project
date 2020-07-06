#ifndef __COMMON_H__
#define __COMMON_H__

#include <ntddk.h>
#include <aux_klib.h>
#include <Ntstrsafe.h>


typedef struct ModuleData
{
	PAUX_MODULE_EXTENDED_INFO Data;
	ULONG Length;
} ModuleData, *PModuleData;


typedef struct NodeIat
{
	PCHAR ProcessName;
	ULONG Pid;
	INT64 Checksum;
	BOOLEAN IsHooked;
	struct NodeIat* Next;

} NodeIAT, *PNodeIAT;


typedef struct NodeKernelIat
{
	PCHAR ModuleName;
	ULONG BaseAddress;
	INT64 Checksum;
	BOOLEAN IsHooked;
	struct NodeKernelIat* Next;

} NodeKIAT, *PNodeKIAT;


typedef struct NodeIrp
{
	PUNICODE_STRING DeviceName;
	INT64 Checksum;
	BOOLEAN IsHooked;
	struct NodeIrp* Next;

} NodeIRP, *PNodeIRP;


// Functions
ULONG GetNtoskrnlBase();
ULONG GetNtoskrnlSize();
NTSTATUS InitNtoskrnlVars();
ModuleData GetKernelModuleList();


#endif