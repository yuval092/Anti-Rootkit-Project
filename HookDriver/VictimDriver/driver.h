#pragma once
#ifndef __TEST_DRIVER_H__
#define __TEST_DRIVER_H__

#include <ntddk.h>
#include <wdm.h>

#define IOCTL_TEST 1


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

#endif