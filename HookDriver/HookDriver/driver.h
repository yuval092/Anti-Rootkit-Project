#pragma once
#ifndef __HOOK_DRIVER_H__
#define __HOOK_DRIVER_H__

#include <ntddk.h>
#include <wdm.h>

// ioctl codes

//#define SIOCTL_TYPE 40000
//#define IOCTL_SSDT\
// CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_SSDT 1
#define IOCTL_IRP 2
#define IOCTL_IDT 3
#define IOCTL_UNHOOK 4


// Dispatch Declarations

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnloadHandler;

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH IrpCreateHandler;

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH IrpCloseHandler;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH IrpDeviceIoCtlHandler;

__drv_dispatchType(IRP_MJ_CREATE_NAMED_PIPE)
DRIVER_DISPATCH IrpNotImplementedHandler;



// Function Definitions

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

VOID DriverUnloadHandler(
	_In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS IrpCreateHandler(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

NTSTATUS IrpCloseHandler(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

NTSTATUS IrpDeviceIoCtlHandler(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

NTSTATUS IrpNotImplementedHandler(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);







// ---------------------------------------------------------------------------------------------------------------------
// SSDT Functions

void DisableWP();

void EnableWP();

NTSTATUS HookSSDT(PUCHAR syscall, PUCHAR hookaddr);

NTSTATUS Hook_ZwCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
);



// SSDT Structeres & Imports

typedef struct SystemServiceDescriptorTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}SSDT, *PSSDT;

__declspec(dllimport) PSSDT KeServiceDescriptorTable;

__declspec(dllimport) NTSTATUS NTAPI ZwCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
);

typedef NTSTATUS(*ZwCreateFilePrototype)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
	);

ZwCreateFilePrototype oldZwCreateFile = NULL;


// ---------------------------------------------------------------------------------------------------------------------
// IRP Functions

NTSTATUS HookIRP(ULONG HookRoutine);

NTSTATUS IrpHookRoutine(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);


// IRP Variables

typedef NTSTATUS(*IrpFunctionPtr)
(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	);

IrpFunctionPtr OldIrp = NULL;

PFILE_OBJECT   HookedFile = NULL;
PDEVICE_OBJECT HookedDevice = NULL;
PDRIVER_OBJECT HookedDriver = NULL;


// ---------------------------------------------------------------------------------------------------------------------
// IDT Functions


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


NTSTATUS HookIDT(USHORT Service, ULONG HookAddr);
VOID IdtHookRoutine(ULONG d);
ULONG GetISRAddress(USHORT Service);
IDTR GetIDTAddress();
PDESC GetDescriptorAddress(USHORT Service);
HookRoutine();

ULONG OldISRAddress = 0;


#endif