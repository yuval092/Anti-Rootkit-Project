#include "driver.h"

/*
	The entry point for the driver.
	Input:  Pointer to the driver object to be created,
			The registery path for the driver (not used).
	Output: Status of the procedure (succeded or not).
*/
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UINT32 i = 0;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING DeviceName, SymLinkeName = { 0 };

	UNREFERENCED_PARAMETER(RegistryPath);
	PAGED_CODE();							// what is this?

	RtlInitUnicodeString(&DeviceName, L"\\Device\\VictimDriver");
	RtlInitUnicodeString(&SymLinkeName, L"\\??\\VictimDriver");

	
	// Create the device
	Status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject
	);

	if (!NT_SUCCESS(Status))
	{
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);

		DbgPrint("[-] Error Creating IO Device \r\n");
		return Status;
	}


	// Assign the IRP handlers
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = IrpNotImplementedHandler;
	}


	// Assign the IRP handlers for Create, Close and Device Control
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;


	// Assign the driver Unload routine
	DriverObject->DriverUnload = DriverUnloadHandler;


	// Set the flags
	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;


	// Create the symbolic link
	Status = IoCreateSymbolicLink(&SymLinkeName, &DeviceName);

	DbgPrint("[+] Victim: Driver Loaded \r\n");
	return Status;
}


/*
	Unload the driver from the kernel memory space.
	Input:  Pointer to the driver object to be deleted.
	Output: None.
*/
VOID DriverUnloadHandler(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING SymLinkName = { 0 };

	PAGED_CODE();

	RtlInitUnicodeString(&SymLinkName, L"\\??\\VictimDriver");

	// Delete the symbolic link
	IoDeleteSymbolicLink(&SymLinkName);

	// Delete the device
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("[+] Driver Unloaded \r\n");
}


/*
	The Handler for the create IRP.
	Input:  Pointer to the driver object to be deleted,
			Pointer to the IRP object.
	Output: Status of the procedure (succeded or not).
*/
NTSTATUS IrpCreateHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	DbgPrint("[+] Victim: Entered IrpCreateHandler \r\n");

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


/*
	The Handler for the close IRP.
	Input:  Pointer to the driver object to be deleted,
			Pointer to the IRP object.
	Output: Status of the procedure (succeded or not).
*/
NTSTATUS IrpCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	DbgPrint("[+] Victim: Entered IrpCloseHandler \r\n");

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


/*
	The Handler for the ioctl IRP. this IRP is different than other IRPs
	because it is not a specific task, but a generic input/output procedure.
	Input:  Pointer to the driver object to be deleted,
			Pointer to the IRP object.
	Output: Status of the procedure (succeded or not).
*/
NTSTATUS IrpDeviceIoCtlHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	DbgPrint("[+] Victim: Entered IrpDeviceIoCtlHandler \r\n");

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_NOT_SUPPORTED;
}


/*
	The Handler for all the not implemented IRPs.
	Input:  Pointer to the driver object to be deleted,
			Pointer to the IRP object.
	Output: Status of the procedure (succeded or not).
*/
NTSTATUS IrpNotImplementedHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	DbgPrint("[+] Victim: Entered IrpNotImplementedHandler \r\n");

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_NOT_SUPPORTED;
}