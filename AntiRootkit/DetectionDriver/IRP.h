#ifndef __IRP_H__
#define __IRP_H__

#include "Common.h"

// ----------------------------------------------------------------------------------------------
// Functions

NTSTATUS CreateNewNode(INT64 Value, PUNICODE_STRING Name);
INT64    CalculateChecksum(PDRIVER_OBJECT DriverObject);
NTSTATUS WriteIrpScanResults(HANDLE Handle);
NTSTATUS InitIrpLinkedList();
NTSTATUS InitDeviceList();
NTSTATUS InitVarsIRP();
NTSTATUS UnloadIRP();
NTSTATUS ScanIRP();


// ----------------------------------------------------------------------------------------------
// Defines and imports

NTKERNELAPI NTSTATUS NTAPI ZwOpenDirectoryObject(
	_Out_ PHANDLE            DirectoryHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes
);


NTKERNELAPI NTSTATUS NTAPI ZwQueryDirectoryObject(
	_In_      HANDLE  DirectoryHandle,
	_Out_opt_ PVOID   Buffer,
	_In_      ULONG   Length,
	_In_      BOOLEAN ReturnSingleEntry,
	_In_      BOOLEAN RestartScan,
	_Inout_   PULONG  Context,
	_Out_opt_ PULONG  ReturnLength
);


typedef struct _OBJECT_DIRECTORY_INFORMATION
{
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION;


#endif