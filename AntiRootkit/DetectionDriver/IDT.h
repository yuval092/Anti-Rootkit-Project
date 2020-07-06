#ifndef __IDT_H__
#define __IDT_H__

#include "Common.h"

// ---------------------------------------------------------------------------------------------------------------------
// Structures

#pragma pack(1)
typedef struct _DESC {
	UINT16 offset00;
	UINT16 segsel;
	CHAR unused : 5;
	CHAR zeros : 3;
	CHAR type : 5;
	CHAR DPL : 2;
	CHAR P : 1;
	UINT16 offset16;
} DESC, *PDESC;
#pragma pack()


#pragma pack(1)
typedef struct _IDTR {
	UINT16 bytes;
	UINT32 addr;
} IDTR;
#pragma pack()


// ---------------------------------------------------------------------------------------------------------------------
// Functions

NTSTATUS ScanIDT();
NTSTATUS UnloadIDT();
IDTR GetIDTAddress();
NTSTATUS InitVarsIDT();
ULONG GetISRAddress(USHORT Service);
PDESC GetDescriptorAddress(USHORT Service);
NTSTATUS WriteIdtScanResults(HANDLE Handle);

#endif