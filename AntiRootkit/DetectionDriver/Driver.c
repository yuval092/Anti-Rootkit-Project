#include "Driver.h"

#define BUFFER_ERROR_SIZE 12
#define SCAN_RESULT_FILE_PATH L"\\??\\C:\\Windows\\System32\\ScanResult.txt"

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
	UNICODE_STRING DeviceName = { 0 }, SymLinkName = { 0 };

	UNREFERENCED_PARAMETER(RegistryPath);
	PAGED_CODE();
	
	RtlInitUnicodeString(&DeviceName, L"\\Device\\DetectionDriver");
	RtlInitUnicodeString(&SymLinkName, L"\\??\\DetectionDriver");

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
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;


	// Assign the driver Unload routine
	DriverObject->DriverUnload = DriverUnloadHandler;


	// Set the flags
	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;


	// Create the symbolic link
	Status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
	if (!NT_SUCCESS(Status))
	{
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);

		DbgPrint("[-] Error Creating Symoblic Link \r\n");
		return Status;
	}


	// Initalize Ntoskrnl variables
	if (!NT_SUCCESS(InitNtoskrnlVars()))
	{
		DbgPrint("[***] CRITICAL ERROR: Failed to init ntoskrnl variables!\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Initalize SSDT scan variables
	if (!NT_SUCCESS(InitVarsSSDT()))
	{
		DbgPrint("[***] CRITICAL ERROR: Failed to init SSDT variables!\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	//Initalize IRP scan variables
	if (!NT_SUCCESS(InitVarsIRP()))
	{
		DbgPrint("[***] CRITICAL ERROR: Failed to init IRP variables!\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (!NT_SUCCESS(InitVarsIDT()))
	{
		DbgPrint("[***] CRITICAL ERROR: Failed to init IDT variables!\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (!NT_SUCCESS(InitVarsIAT()))
	{
		DbgPrint("[***] CRITICAL ERROR: Failed to init IAT variables!\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (!NT_SUCCESS(InitVarsKIAT()))
	{
		DbgPrint("[***] CRITICAL ERROR: Failed to init KIAT variables!\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("[+] Driver Loaded \r\n");
	return Status;
}


/*
	Unload the driver from the kernel memory space.
	Input:  Pointer to the driver object to be deleted,
	Output: None.
*/
VOID DriverUnloadHandler(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING SymLinkName = { 0 };

	PAGED_CODE();

	RtlInitUnicodeString(&SymLinkName, L"\\??\\DetectionDriver");

	// Free dynamic memory
	if (!NT_SUCCESS(UnloadSSDT()))
		DbgPrint("[-] Failed to unload the SSDT scanner. There might be memory leaks \r\n");

	if (!NT_SUCCESS(UnloadIRP()))
		DbgPrint("[-] Failed to unload the IRP scanner. There might be memory leaks \r\n");

	if (!NT_SUCCESS(UnloadIDT()))
		DbgPrint("[-] Failed to unload the IDT scanner. There might be memory leaks \r\n");

	if (!NT_SUCCESS(UnloadIAT()))
		DbgPrint("[-] Failed to unload the IAT scanner. There might be memory leaks \r\n");

	if (!NT_SUCCESS(UnloadKIAT()))
		DbgPrint("[-] Failed to unload the Kernel IAT scanner. There might be memory leaks \r\n");

	// Delete the symbolic link
	IoDeleteSymbolicLink(&SymLinkName);

	// Delete the device
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("[+] Driver Unloaded \r\n");
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
	PIO_STACK_LOCATION irpSp;
	ModuleData Module;
	NTSTATUS Status;
	PULONG input;
	ULONG i;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);

	if (irpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCAN_HOOKS)
	{
		// Iterate the module list, add every new module and remove any invalid modules
		Module = GetKernelModuleList();
		if (Module.Data == NULL || Module.Length == 0)
		{
			DbgPrint("[-] Failed to get kernel module list \r\n");
			Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			goto end;
		}

		for (i = 0; i < Module.Length; ++i)
		{
			Status = AddNewKernelModule(
				Module.Data[i].FullPathName,
				Module.Data[i].BasicInfo.ImageBase
			);
			if (!NT_SUCCESS(Status))
			{
				DbgPrint("[-] Failed to add kernel module: %s \r\n", Module.Data[i].FullPathName);
			}
		}
		ExFreePool(Module.Data);

		Status = HandleDetection();	// The user application will call this ioctl every few seconds
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to perform scan \r\n");
			WriteToExternalFile(TRUE);
		}

		Irp->IoStatus.Status = Status;
	}
	else if (irpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_ADD_NEW_PROCESS)
	{
		// Need to get input buffer from user-mode containing the pid!
		input = (PULONG)Irp->AssociatedIrp.SystemBuffer;
		if (input == NULL)
		{
			DbgPrint("[-] Request input is invalid \r\n");
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			goto end;
		}
		
		Status = AddNewProcess(*input);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to add new process \r\n");
			Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			goto end;
		}
	}
	else
	{
		DbgPrint("[-] Invalid IOCTL code \r\n");
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		goto end;
	}

	// All good
	Irp->IoStatus.Status = STATUS_SUCCESS;

end:
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


/*
	The Handler for the create & close IRP.
	Input:  Pointer to the driver object to be deleted,
			Pointer to the IRP object.
	Output: Status of the procedure (succeded or not).
*/
NTSTATUS IrpCreateCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


/*
	The Handler for all the not implemented IRPs.
	Input:  Pointer to the driver object to be deleted,
			Pointer to the IRP object.
	Output: Status of the procedure (succeded or not).
*/
NTSTATUS IrpNotImplementedHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_NOT_SUPPORTED;
}


// ----------------------------------------------------------------------------------------------
// Scan Related Functions


/*
	Handle the detection of all types of hooks.
	Steps:
	1. Init all variables required for the scans.
	2. Init the lists responsible for transfering data.
	3. Perform the scans in a loop.
	Input: None.
	Output: Status of the procedure (succeded or not).
*/
NTSTATUS HandleDetection()
{
	NTSTATUS Status;

	PAGED_CODE();


	// Perform all scans
	Status = ScanSSDT();
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] SSDT scan failed \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	Status = ScanIRP();
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] IRP scan failed \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	Status = ScanIDT();
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] IDT scan failed \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	Status = ScanIAT();
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] IAT scan failed \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	Status = ScanKIAT();
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Kernel IAT scan failed \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Write scan results to external file
	if (!NT_SUCCESS(WriteToExternalFile(FALSE)))
	{
		DbgPrint("[-] Failed to write scan results to external file \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


/*
	Write Scan results to external file in order
	to deliever the data to the user mode application.
	Input: None.
	Output: Status of the procedure (succeded or not).
*/
NTSTATUS WriteToExternalFile(BOOLEAN Error)
{
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK IoBlock;
	HANDLE Handle = NULL;
	PCHAR Buffer = NULL;
	UNICODE_STRING uStr;
	NTSTATUS Status;

	// Make sure my IRQL is 0 (Passive), so i will not
	// interrupt any dispatching of the os
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	RtlInitUnicodeString(&uStr, SCAN_RESULT_FILE_PATH);
	InitializeObjectAttributes(&objAttr, &uStr,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	// Open the text file
	Status = ZwCreateFile(
		&Handle,
		GENERIC_WRITE,
		&objAttr,
		&IoBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to open results file \r\n");
		goto finish;
	}

	// An error has occured, write error message to the text file
	if (Error == TRUE)
	{
		Buffer = ExAllocatePool(PagedPool, BUFFER_ERROR_SIZE);
		if (Buffer == NULL)
		{
			DbgPrint("[-] Failed to allocate memory \r\n");
			goto finish;
		}
		RtlZeroMemory(Buffer, BUFFER_ERROR_SIZE);

		RtlStringCbCopyA(Buffer, BUFFER_ERROR_SIZE, "[-] Error\n");
		Status = ShortenedZwWriteFile(Handle, Buffer);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to write error to the text file \r\n");
		}

		ExFreePool(Buffer);
		goto finish;
	}

	// write SSDT results to the text file
	Status = WriteSsdtScanResults(Handle);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to write SSDT results to the text file \r\n");
		goto finish;
	}

	// Write IRP results to the text file
	Status = WriteIrpScanResults(Handle);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to write IRP results to the text file \r\n");
		goto finish;
	}

	// Write idt results to the text file
	Status = WriteIdtScanResults(Handle);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to write IDT results to the text file \r\n");
		goto finish;
	}

	// Write iat results to the text file
	Status = WriteIatScanResults(Handle);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to write IAT results to the text file \r\n");
	}

	// Write iat results to the text file
	Status = WriteKernelIatScanResults(Handle);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to write KIAT results to the text file \r\n");
	}


finish:
	ZwClose(Handle);
	return Status;
}


/*
	Short form of the ZwWriteFile function.
	Input: The file handle and a buffer to write.
	Output: the output of ZwWriteFile.
*/
NTSTATUS ShortenedZwWriteFile(HANDLE Handle, PCHAR Buffer)
{
	IO_STATUS_BLOCK IoBlock;

	if (Handle == NULL || Buffer == NULL)
		return STATUS_UNSUCCESSFUL;

	return ZwWriteFile(
		Handle,
		NULL,
		NULL,
		NULL,
		&IoBlock,
		Buffer,
		strlen(Buffer) + 1,
		NULL,
		NULL
	);
}