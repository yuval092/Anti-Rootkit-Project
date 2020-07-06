#include "IRP.h"

// Global variables
PUNICODE_STRING DeviceList;
PNodeIRP FirstNodeIRP;
ULONG DeviceListSize;
ULONG IrpListSize;

#define SIZE 0X800
#define LINE_SIZE 8		//IRP|<Name>|0\n

// ----------------------------------------------------------------------------------------------
// IRP Functions


/*
	Init the variables required for the IRP scan. This function
	is being run when the driver starts.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS InitVarsIRP()
{
	// Zero out global variables
	FirstNodeIRP = NULL;
	DeviceListSize = 0;
	DeviceList = NULL;
	IrpListSize = 0;

	// Initalize IRP scan variables
	if (!NT_SUCCESS(InitDeviceList()))
	{
		DbgPrint("[-] Failed to init device list \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Initalize the linked list according to the device list
	if (!NT_SUCCESS(InitIrpLinkedList()))
	{
		DbgPrint("[-] Failed to init IRP linked list \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


/*
	Free any resources used by the IRP scanner.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS UnloadIRP()
{
	PNodeIRP temp;
	ULONG i;

	// Free device list
	for (i = 0; i < DeviceListSize - 1; ++i)
	{
		ExFreePool(DeviceList[i].Buffer);
	}
	ExFreePoolWithTag(DeviceList, 'List');

	// Free linked list
	while (FirstNodeIRP != NULL)
	{
		temp = FirstNodeIRP;
		FirstNodeIRP = temp->Next;

		ExFreePool(temp->DeviceName->Buffer);		// The name buffer
		ExFreePool(temp->DeviceName);				// The name struct
		ExFreePool(temp);					// The node itself
	}

	return STATUS_SUCCESS;
}


/*
	Scan every kernel device for IRP hook.
	Steps:
	1.	Check if all init's were complete.
	2.	Free device list (free every unicode string buffer and the list itself).
	3.	Init device list again
	4.	Iterate all driver objects for new device list
	5.	For every driver object check if it is in the linked list (by name).
		If the driver is in the linked list, get its checksum and compare
		it with the checksum in the linked list. if the same, all good.
		if not, we detected a hook!
	6.	If the driver is not in the linked list, allocate a new node to
		the linked list and set the required struct members.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS ScanIRP()
{
	PDEVICE_OBJECT DeviceObj = NULL;
	PDRIVER_OBJECT DriverObj = NULL;
	PFILE_OBJECT FileObj = NULL;
	PNodeIRP CurrentNode = NULL;
	NTSTATUS Status;
	INT64 Checksum;
	ULONG i;

	// Step 1
	if (DeviceList == NULL || FirstNodeIRP == NULL)
	{
		DbgPrint("[-] IRP variables initialization did not occur \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Step 2
	for (i = 0; i < DeviceListSize - 1; ++i)
	{
		ExFreePool(DeviceList[i].Buffer);
	}
	ExFreePoolWithTag(DeviceList, 'List');


	// Step 3
	Status = InitDeviceList();
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Device list re-initialization failed \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Step 4
	for (i = 0; DeviceList[i].Length != 0; ++i)	// Length is the first element
	{
		// Get the driver device object
		Status = IoGetDeviceObjectPointer(
			DeviceList + i,
			FILE_READ_DATA,
			&FileObj,
			&DeviceObj
		);
		if (!NT_SUCCESS(Status))	// May occur multiple times since not all device
		{							// drivers have a functional create irp handler.
			continue;
		}

		DriverObj = DeviceObj->DriverObject;

		// Step 5
		CurrentNode = FirstNodeIRP;
		while (CurrentNode != NULL)
		{
			// If the current driver is in the linked list
			if (RtlEqualUnicodeString(CurrentNode->DeviceName, DeviceList + i, TRUE))
			{
				Checksum = CalculateChecksum(DriverObj);
				if (Checksum != CurrentNode->Checksum)
					CurrentNode->IsHooked = TRUE;
				else
					CurrentNode->IsHooked = FALSE;

				break;
			}

			CurrentNode = CurrentNode->Next;
		}

		// Step 6
		if (CurrentNode == NULL)	// Driver not in linked list
		{
			Checksum = CalculateChecksum(DriverObj);
			Status = CreateNewNode(Checksum, DeviceList + i);
			if (!NT_SUCCESS(Status))
			{
				DbgPrint("[-] Failed to insert new node to the linked list \r\n");
				return STATUS_UNSUCCESSFUL;
			}
		}
	}

	return STATUS_SUCCESS;
}


/*
	Init the device list variable by iterating through
	the device directory.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS InitDeviceList()
{
	ULONG PreviousContext = 0, Context = 0, i = 0;
	OBJECT_DIRECTORY_INFORMATION* Info = NULL;
	ULONG DeviceLen = 0, NameLen = 0;
	UNICODE_STRING uDeviceString;
	OBJECT_ATTRIBUTES Obj;
	HANDLE hFile;


	RtlInitUnicodeString(&uDeviceString, L"\\Device");

	Info = (OBJECT_DIRECTORY_INFORMATION*)ExAllocatePoolWithTag(PagedPool, SIZE, 'Info');
	RtlZeroMemory(Info, SIZE);

	InitializeObjectAttributes(&Obj, &uDeviceString, 0, NULL, NULL);
	if (!NT_SUCCESS(ZwOpenDirectoryObject(&hFile, 0x20001, &Obj)))
		return STATUS_UNSUCCESSFUL;

	// Get device list size
	ZwQueryDirectoryObject(hFile, Info, SIZE, TRUE, FALSE, &Context, NULL);
	while (PreviousContext != Context)
	{
		PreviousContext = Context;
		ZwQueryDirectoryObject(hFile, Info, SIZE, TRUE, FALSE, &Context, NULL);
	}

	// Now create the list of devices
	DeviceList = ExAllocatePoolWithTag(PagedPool, (Context + 1) * sizeof(UNICODE_STRING), 'List');
	RtlZeroMemory(DeviceList, (Context + 1) * sizeof(UNICODE_STRING));
	DeviceListSize = Context + 1;
	Context = 0;
	for (i = 0; i < PreviousContext; ++i)
	{
		ZwQueryDirectoryObject(hFile, Info, SIZE, TRUE, FALSE, &Context, NULL);

		// Instead of using RtlCreateUnicodeString.
		// We need to start every Device name with '\\Device\\' and then append.
		RtlInitUnicodeString(&uDeviceString, L"\\Device\\");
		NameLen = Info->Name.Length;
		DeviceLen = uDeviceString.Length;

		DeviceList[i].Length = (USHORT)(NameLen + DeviceLen);
		DeviceList[i].MaximumLength = (USHORT)(Info->Name.MaximumLength + DeviceLen);
		DeviceList[i].Buffer = ExAllocatePool(PagedPool, DeviceList[i].MaximumLength);
		RtlZeroMemory(DeviceList[i].Buffer, DeviceList[i].MaximumLength);

		RtlCopyMemory(DeviceList[i].Buffer, uDeviceString.Buffer, DeviceLen);
		RtlCopyMemory((PVOID)((ULONG)DeviceList[i].Buffer + DeviceLen), Info->Name.Buffer, NameLen);
	}

	ExFreePoolWithTag(Info, 'Info');
	return STATUS_SUCCESS;
}


/*
	Init the linked list which represents the IRP table
	of every currently loaded device driver in the kernel.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS InitIrpLinkedList()
{
	PDEVICE_OBJECT DeviceObj = NULL;
	PFILE_OBJECT FileObj = NULL;
	INT64 Value = 0;
	NTSTATUS Status;
	ULONG i;

	for (i = 0; DeviceList[i].Length != 0; ++i)	// Length is the first element
	{
		// Get the driver device object
		Status = IoGetDeviceObjectPointer(
			DeviceList + i,
			FILE_READ_DATA,
			&FileObj,
			&DeviceObj
		);
		if (!NT_SUCCESS(Status))
		{
			// DbgPrint("[-] Failed to get device object of driver. index: %d \r\n", i);
			continue;
		}

		Value = CalculateChecksum(DeviceObj->DriverObject);
		Status = CreateNewNode(Value, DeviceList + i);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to create new node \r\n");
			return Status;
		}
	}

	return STATUS_SUCCESS;
}


/*
	Create a new node and insert it to the linked list.
	Input: The checksum of the new node its name.
	Output: Whether the function was successful or not.
*/
NTSTATUS CreateNewNode(INT64 Value, PUNICODE_STRING Name)
{
	PNodeIRP NewNode = NULL;

	NewNode = ExAllocatePool(PagedPool, sizeof(NodeIRP));
	if (NewNode == NULL)
		return STATUS_UNSUCCESSFUL;
	RtlZeroMemory(NewNode, sizeof(NodeIRP));	// Next is set to NULL

	// Set value
	NewNode->Checksum = Value;

	// Set name
	NewNode->DeviceName = ExAllocatePool(PagedPool, sizeof(UNICODE_STRING));
	if (NewNode->DeviceName == NULL)
		return STATUS_UNSUCCESSFUL;
	RtlZeroMemory(NewNode->DeviceName, sizeof(UNICODE_STRING));
	NewNode->DeviceName->Length = Name->Length;
	NewNode->DeviceName->MaximumLength = Name->MaximumLength;
	NewNode->DeviceName->Buffer = ExAllocatePool(PagedPool, Name->MaximumLength);
	if (NewNode->DeviceName->Buffer == NULL)
		return STATUS_UNSUCCESSFUL;
	RtlZeroMemory(NewNode->DeviceName->Buffer, Name->MaximumLength);
	RtlCopyMemory(NewNode->DeviceName->Buffer, Name->Buffer, Name->Length);


	// Adjust linked list
	if (FirstNodeIRP == NULL)
	{
		FirstNodeIRP = NewNode;
	}
	else
	{
		PNodeIRP Temp = FirstNodeIRP;
		PNodeIRP PreTemp = Temp;
		
		while (Temp != NULL)
		{
			PreTemp = Temp;
			Temp = Temp->Next;
		}

		PreTemp->Next = NewNode;
	}

	IrpListSize++;

	return STATUS_SUCCESS;
}


/*
	Calculate the checksum of a given IRP table by the
	following formula: result = sum ^ (sum % 1000) + 0x92
	when sum is the sum of all addresses in the IRP table.
	Input:	Pointer to the IRP table of a driver.
	Output: The calculated checksum.
*/
INT64 CalculateChecksum(PDRIVER_OBJECT DriverObject)
{
	INT64 Sum = 0;
	ULONG i;

	for (i = IRP_MJ_CREATE; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		Sum += (ULONG)((DriverObject->MajorFunction[i]));
	}

	Sum ^= (Sum % 1000);
	Sum += 0x92;

	return Sum;
}


/*
	Write a buffer to an external file which will contain
	the results of the IRP scan. The results will be in
	the following format: 'IRP|<DEVICE_NAME>|<HOOKED_OR_NOT>'.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS WriteIrpScanResults(HANDLE Handle)
{
	PNodeIRP Temp = FirstNodeIRP;
	IO_STATUS_BLOCK IoBlock;
	ANSI_STRING Name;
	ULONG BufferSize;
	NTSTATUS Status;
	PCHAR Buffer;

	// Init variables
	Name.Buffer = NULL;
	Buffer = NULL;

	while (Temp != NULL)
	{
		// Allocate buffer according to name size
		BufferSize = 1 + LINE_SIZE + (Temp->DeviceName->MaximumLength) / 2;
		Buffer = (PCHAR)ExAllocatePool(PagedPool, BufferSize);
		if (Buffer == NULL)
		{
			DbgPrint("[-] Failed to allocate memory \r\n");
			goto error;
		}
		RtlZeroMemory(Buffer, BufferSize);

		// Copy 'IRP|' to the buffer
		Status = RtlStringCbCopyA(Buffer, BufferSize, "IRP|");
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to copy a string \r\n");
			goto error;
		}

		// Convert the unicode string to ansi string
		Status = RtlUnicodeStringToAnsiString(&Name, Temp->DeviceName, TRUE);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to convert UNICODE string to ASCI string \r\n");
			goto error;
		}

		// Concatenate the device name to the buffer
		Status = RtlStringCbCatA(Buffer, BufferSize, Name.Buffer);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to concatenate a string \r\n");
			goto error;
		}
		ExFreePool(Name.Buffer);

		// Concatenate whether the irp was hooked or not
		if (Temp->IsHooked == TRUE)
			Status = RtlStringCbCatA(Buffer, BufferSize, "|1\n");
		else
			Status = RtlStringCbCatA(Buffer, BufferSize, "|0\n");
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to concatenate a string \r\n");
			goto error;
		}

		// Write buffer to the external file
		Status = ZwWriteFile(
			Handle,
			NULL,
			NULL,
			NULL,
			&IoBlock,
			Buffer,
			strlen(Buffer),
			NULL,
			NULL
		);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to write to a text file \r\n");
			goto error;
		}
		ExFreePool(Buffer);

		Temp = Temp->Next;
	}

	return STATUS_SUCCESS;

error:
	if (Name.Buffer != NULL)
		ExFreePool(Name.Buffer);
	if (Buffer != NULL)
		ExFreePool(Buffer);
	return STATUS_UNSUCCESSFUL;
}