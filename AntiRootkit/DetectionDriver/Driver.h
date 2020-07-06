#pragma once
#ifndef __DRIVER_H__
#define __DRIVER_H__

#include "SSDT.h"
#include "KIAT.h"
#include "IRP.h"
#include "IDT.h"
#include "IAT.h"

// ----------------------------------------------------------------------------------------------
// Defines

#define IOCTL_SCAN_HOOKS 1
#define IOCTL_ADD_NEW_PROCESS 2


// ----------------------------------------------------------------------------------------------
// Dispatch Declarations

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnloadHandler;

__drv_dispatchType(IRP_MJ_CREATE)
__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH IrpCreateCloseHandler;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH IrpDeviceIoCtlHandler;

__drv_dispatchType(IRP_MJ_CREATE_NAMED_PIPE)
DRIVER_DISPATCH IrpNotImplementedHandler;


// ----------------------------------------------------------------------------------------------
// Driver Required Functions

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

VOID DriverUnloadHandler(
	_In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS IrpCreateCloseHandler(
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


// ----------------------------------------------------------------------------------------------
// Scan Related Functions

NTSTATUS ShortenedZwWriteFile(HANDLE Handle, PCHAR Buffer);
NTSTATUS WriteToExternalFile(BOOLEAN Error);
NTSTATUS HandleDetection();


#endif