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
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName, SymLinkeName = { 0 };

	UNREFERENCED_PARAMETER(RegistryPath);
	PAGED_CODE();							// what is this?

	RtlInitUnicodeString(&DeviceName, L"\\Device\\HookDriver");
	RtlInitUnicodeString(&SymLinkeName, L"\\??\\HookDriver");


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

	RtlInitUnicodeString(&SymLinkName, L"\\??\\HookDriver");

	// Restore the hook
	if (oldZwCreateFile != NULL)
	{
		oldZwCreateFile = (ZwCreateFilePrototype)HookSSDT((PUCHAR)ZwCreateFile, (PUCHAR)oldZwCreateFile);
		EnableWP();
		DbgPrint("[+] The original SSDT function restored \r\n");
	}

	if (OldISRAddress != NULL)
	{
		if (!NT_SUCCESS(HookIDT(0x2e, (ULONG)OldISRAddress)))
			DbgPrint("[-] Failed to restore IDT hook \r\n");
		else
			DbgPrint("[+] The original IDT function restored \r\n");
	}

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
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IrpSp = NULL;
	ULONG IoctlCode = 0;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	IoctlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
	if (IoctlCode == IOCTL_SSDT)
	{
		Status = HookSSDT((PUCHAR)ZwCreateFile, (PUCHAR)Hook_ZwCreateFile);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to hook the SSDT \r\n");
		}
		else
		{
			DbgPrint("[+] SSDT hook was successful \r\n");
		}
	}
	else if (IoctlCode == IOCTL_IRP)
	{
		Status = HookIRP((ULONG)IrpHookRoutine);					// I should pass the name of the victim driver...
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to hook the IRP \r\n");
		}
		else
		{
			DbgPrint("[+] Irp hook was successful \r\n");
		}
	}
	else if (IoctlCode == IOCTL_IDT)
	{
		Status = HookIDT(0x2e, (ULONG)HookRoutine);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to hook the IDT \r\n");
		}
		else
		{
			DbgPrint("[+] IDT hook was successful \r\n");
		}
	}
	else if (IoctlCode == IOCTL_UNHOOK)
	{
		// Restore the SSDT hook
		if (oldZwCreateFile != NULL)
		{
			oldZwCreateFile = (ZwCreateFilePrototype)HookSSDT((PUCHAR)ZwCreateFile, (PUCHAR)oldZwCreateFile);
			EnableWP();
			DbgPrint("[+] The original SSDT function restored \r\n");
		}

		// Restore the IDT hook
		if (OldISRAddress != NULL)
		{
			if (!NT_SUCCESS(HookIDT(0x2e, (ULONG)OldISRAddress)))
				DbgPrint("[-] Failed to restore IDT hook \r\n");
			else
				DbgPrint("[+] The original IDT function restored \r\n");
		}

		// Restore the IRP hook
		if (OldIrp != NULL)
		{
			if (!NT_SUCCESS(HookIRP(OldIrp)))
				DbgPrint("[-] Failed to restore IRP hook \r\n");
			else
				DbgPrint("[+] The original IRP function restored \r\n");
		}
	}
	else
	{
		DbgPrint("[-] UNSUPPORTED IOCTL \r\n");
	}

	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
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



// ------------------------------------------------------------------------------------------------------------------------------------------------------
// SSDT stuff


// Disable the WP bit in CR0 register.
void DisableWP()
{
	__asm
	{
		push edx;
		mov edx, cr0;
		and edx, 0xFFFEFFFF;
		mov cr0, edx;
		pop edx;
	}
}


// Enable the WP bit in CR0 register.
void EnableWP()
{
	__asm
	{
		push edx;
		mov edx, cr0;
		or edx, 0x00010000;
		mov cr0, edx;
		pop edx;
	}
}


/*
 * A function that hooks the 'syscall' function in SSDT.
 */
NTSTATUS HookSSDT(PUCHAR syscall, PUCHAR hookaddr)
{
	UINT32 index;
	PULONG target;

	// disable WP (write protect) bit in CR0 to enable writing to SSDT
	DisableWP();
	DbgPrint("[+] The WP flag in CR0 has been disabled \r\n");

	// Get the syscall index in the SST.
	// This is a cool trick since the first instruction in the 
	// ntdll routine is mov eax, <id>; and "mov eax" is b8 in 
	// machine code (one byte), so adding 1 byte will get the id.
	index = *((PULONG)(syscall + 0x1));
	DbgPrint("[+] The index into the SSDT table is: 0x%x \r\n", index);

	// Get the address of the service routine in SSDT
	target = (PULONG)((UINT32)KeServiceDescriptorTable + (UINT32)(4 * index));
	DbgPrint("[+] About to: *v1 = v2 when v1 is the ssdt routine pointer=0x%x \r\nand v2 is the hook function=0x%x \r\n", target, hookaddr);

	// Set the new address for the hook function in atomic manner
	oldZwCreateFile = (ZwCreateFilePrototype)((PUCHAR)InterlockedExchange((PLONG)target, (LONG)hookaddr));

	// To avoid BSOD
	EnableWP();

	return STATUS_SUCCESS;
}


/*
	The hook function. The function to be called instead of the real function.
	Input: same parameters as the real ZwCreateFile.
	Output: Status of the procedure (succeded or not).
*/
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
	ULONG              EaLength)
{
	NTSTATUS status;

	status = oldZwCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength
	);
	if (!NT_SUCCESS(status))
		DbgPrint("The call to original ZwCreateFile did not succeed \r\n");

	DbgPrint("The call to the hooked ZwCreateFile succeeded \r\n");
	return status;
}



// ------------------------------------------------------------------------------------------------------------------------------------------------------
// IRP stuff


NTSTATUS HookIRP(ULONG HookRoutine)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName;
	RtlInitUnicodeString(&DeviceName, L"\\Device\\VictimDriver");

	// Reset to avoid edge cases
	HookedFile = NULL;
	HookedDevice = NULL;
	HookedDriver = NULL;

	// Get the victim driver device and file objects
	Status = IoGetDeviceObjectPointer(
		&DeviceName,
		FILE_READ_DATA,
		&HookedFile,
		&HookedDevice
	);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to get IRP hook victim driver \r\n");
		return Status;
	}

	// Now that we have the device and file objects, we can hook the IRP
	HookedDriver = HookedDevice->DriverObject;
	OldIrp = HookedDriver->MajorFunction[IRP_MJ_CREATE];	// Arbitrary choice
	DbgPrint("[+] Hook: The IRP list: %p\r\n", &(HookedDriver->MajorFunction));

	if (OldIrp == NULL)	// the IRP_MJ_CREATE routine does not exist
		return STATUS_UNSUCCESSFUL;

	InterlockedExchange((PLONG)&(HookedDriver->MajorFunction), (LONG)HookRoutine);
	DbgPrint("[+] Hook: After InterlockedExchange \r\n");

	return STATUS_SUCCESS;
}


NTSTATUS IrpHookRoutine(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	DbgPrint("[+] Entered the IRP hook routine \r\n");

	NTSTATUS Status = STATUS_SUCCESS;
	if (OldIrp != NULL)
		Status = OldIrp(pDeviceObject, pIrp);	// Just call the actual IRP
												// double override will cause infinite recursion

	return Status;
}



// ------------------------------------------------------------------------------------------------------------------------------------------------------
// IDT stuff


NTSTATUS HookIDT(USHORT Service, ULONG HookAddr)
{
	ULONG  IsrAddr;
	USHORT HookAddrLow;
	USHORT HookAddrHigh;
	PDESC  DescAddr;

	/* check if the ISR was already hooked */
	IsrAddr = GetISRAddress(Service);
	if (IsrAddr == HookAddr)
	{
		DbgPrint("The service %x already hooked.\r\n", Service);
	}
	else
	{
		DbgPrint("Hooking interrupt %x: ISR %x --> %x \r\n", Service, IsrAddr, HookAddr);
		DescAddr = GetDescriptorAddress(Service);
		DbgPrint("Hook Address: %x \r\n", HookAddr);
		HookAddrLow = (UINT16)HookAddr;
		HookAddr = HookAddr >> 16;
		HookAddrHigh = (UINT16)HookAddr;
		DbgPrint("Hook Address Lower: %x \r\n", HookAddrLow);
		DbgPrint("Hook Address Higher: %x \r\n", HookAddrHigh);

		__asm { cli }
		DescAddr->offset00 = HookAddrLow;
		DescAddr->offset16 = HookAddrHigh;
		__asm { sti }
	}

	return STATUS_SUCCESS;
}


__declspec(naked) HookRoutine()
{
	KeLowerIrql(PASSIVE_LEVEL);

	__asm {
		pushad;
		pushfd;

		push eax;
		call IdtHookRoutine;

		popfd;
		popad;

		jmp OldISRAddress;
	}
}


VOID IdtHookRoutine(ULONG d)
{
	DbgPrint("[+] Entered hook routine from dispatch %d \r\n", d);
}


ULONG GetISRAddress(USHORT Service)
{
	PDESC DescAddr;
	ULONG IsrAddr;

	DescAddr = GetDescriptorAddress(Service);

	/* calculate address of ISR from offset00 and offset16 */
	IsrAddr = DescAddr->offset16;
	IsrAddr = IsrAddr << 16;
	IsrAddr += DescAddr->offset00;
	DbgPrint("Address of the ISR is: %x.\r\n", IsrAddr);

	/* store old ISR address in global variable, so we can use it later */
	OldISRAddress = IsrAddr;

	return IsrAddr;
}


IDTR GetIDTAddress()
{
	IDTR IdtrAddr;

	/* get address of the IDT table */
	__asm {
		cli;
		sidt IdtrAddr;
		sti;
	}
	DbgPrint("Address of IDT table is: %x.\r\n", IdtrAddr.addr);

	return IdtrAddr;
}


PDESC GetDescriptorAddress(USHORT Service)
{
	/* allocate local variables */
	IDTR IdtrAddr;
	PDESC DescAddr;

	IdtrAddr = GetIDTAddress();

	/* get address of the interrupt entry we would like to hook */
	DescAddr = (PDESC)(IdtrAddr.addr + Service * 0x8);
	DbgPrint("Address of IDT Entry is: %x.\r\n", DescAddr);

	/* print some statistics */
	DbgPrint("DESC->offset00 : %x\r\n", DescAddr->offset00);
	DbgPrint("DESC->segsel   : %x\r\n", DescAddr->segsel);
	DbgPrint("DESC->type     : %x\r\n", DescAddr->type);
	DbgPrint("DESC->DPL      : %x\r\n", DescAddr->DPL);
	DbgPrint("DESC->P        : %x\r\n", DescAddr->P);
	DbgPrint("DESC->offset16 : %x\r\n", DescAddr->offset16);

	return DescAddr;
}