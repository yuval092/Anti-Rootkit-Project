#include "IAT.h"
#include "myifs.h"

#define FAILED (ULONG)(-1)
#define LINE_SIZE 31		//IAT|<ProcessName>|<Pid>|0\n
#define SIZE_OF_NUMBER 14
#define NAME_SIZE 16
#define DECIMAL 10

// Globals
PNodeIAT FirstNodeIAT;	// processes linked list


/*
	Init the variables required for the IAT scan.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS InitVarsIAT()
{
	FirstNodeIAT = NULL;

	return STATUS_SUCCESS;
}


/*
	Unload the IAT scanner, free all the resources.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS UnloadIAT()
{
	PNodeIAT Temp;

	// Free linked list
	while (FirstNodeIAT != NULL)
	{
		Temp = FirstNodeIAT;
		FirstNodeIAT = FirstNodeIAT->Next;

		ExFreePool(Temp->ProcessName);
		ExFreePool(Temp);
	}

	return STATUS_SUCCESS;
}


/*
	Scan the IAT tables of the known processes which
	are located at the linked list. If there is a checksum
	mismatch, an IAT hook occured. If a process is invalid,
	remove it from the list and free its memory.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS ScanIAT()
{
	NTSTATUS Status = STATUS_SUCCESS;
	PNodeIAT Temp = FirstNodeIAT;
	PNodeIAT Node = NULL;
	ULONG TempPid = 0;

	Node = ExAllocatePool(PagedPool, sizeof(NodeIAT));
	if (Node == NULL)
	{
		DbgPrint("[-] Failed to allocate memory for process \r\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(Node, sizeof(NodeIAT));

	// Iterate the linked list
	while (Temp != NULL)
	{
		Status = ScanProcessIAT(Temp->Pid, Node);
		if (Status == STATUS_ABANDONED)
		{
			DbgPrint("[-] Process '%s' couldn't be accessed \r\n", Temp->ProcessName);

			// To avoid use-after-free
			TempPid = Temp->Pid;
			Temp = Temp->Next;
			RtlZeroMemory(Node, sizeof(NodeIAT));

			RemoveProcessFromList(TempPid);
			continue;
		}
		else if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to scan process '%s' IAT \r\n", Temp->ProcessName);
		}
		else
		{
			if (Node->Checksum != Temp->Checksum)
			{
				DbgPrint("[***] Found IAT Hook at process '%s' \r\n", Temp->ProcessName);
				Temp->IsHooked = TRUE;
			}
		}

		Temp = Temp->Next;
		RtlZeroMemory(Node, sizeof(NodeIAT));
	}

	ExFreePool(Node);
	return STATUS_SUCCESS;
}


/*
	A new process was created and the driver was notifed by
	the user mode agent. Extract new process' data (name,
	pid, checksum), store in a newly allocated node and
	insert it to the linked list.
	Input: ProcessId - the pid of the process.
	Output: Whether the function was successful or not.
*/
NTSTATUS AddNewProcess(
	ULONG ProcessId
)
{
	PNodeIAT NewNode = NULL;
	NTSTATUS Status;

	// Allocate a new node to be used and zero its memory.
	NewNode = ExAllocatePool(PagedPool, sizeof(NodeIAT));
	if (NewNode == NULL)
	{
		DbgPrint("[-] Failed to allocate memory for new process \r\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(NewNode, sizeof(NodeIAT));

	// Set the new node values by iterating the current process IAT.
	Status = ScanProcessIAT(ProcessId, NewNode);
	if (!NT_SUCCESS(Status) || Status == STATUS_ABANDONED)
	{
		DbgPrint("[-] Failed to scan new process \r\n");
		goto free;
	}

	// If all went well, insert the new node to the linked list of open processes.
	Status = AddProcessToList(NewNode);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to add new process to the linked list \r\n");
		goto free;
	}
	else if (Status == STATUS_ABANDONED)
	{
		DbgPrint("[-] New process was a duplicate \r\n");
		goto free;
	}

	return STATUS_SUCCESS;

free:
	if (NewNode != NULL)
		ExFreePool(NewNode);

	return STATUS_UNSUCCESSFUL;
}


/*
	Helper function. Scan the IAT of a given process
	and return its node structure filled. Will be called
	by the AddNewProcess function and ScanIAT function.
	Input:  Pid - the id of the process to be scanned.
			ProcNode - a pointer to an allocated node.
	Output: Whether the function was successful or not.
*/
NTSTATUS ScanProcessIAT(
	ULONG Pid,
	PNodeIAT ProcNode
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS TargetProc = NULL;
	ULONG BaseAddress = 0;
	INT64 Checksum = 0;

	if (ProcNode == NULL)	// Node was not initialized
		return STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Pid, &TargetProc)))
		return STATUS_ABANDONED;

	// Attach the current thread to the address
	// space of the target process. Dangerous!!
	KeAttachProcess((PKPROCESS)TargetProc);

	// Get SectionBaseAddress from EPROCESS
	BaseAddress = (ULONG)PsGetProcessSectionBaseAddress(TargetProc);
	if (BaseAddress == 0)
	{
		DbgPrint("[-] Failed to get process variables for IAT scan \r\n");
		Status = STATUS_ABANDONED;
		goto end;
	}

	Checksum = GetIATChecksum(BaseAddress);
	if (Checksum == FAILED)
	{
		DbgPrint("[-] Failed to scan the IAT for process %d \r\n", Pid);
		Status = STATUS_ABANDONED;
		goto end;
	}

	// Setting values for the new node. The rest are zeroed (NULL/FALSE).
	ProcNode->ProcessName = PsGetProcessImageFileName(TargetProc);
	ProcNode->Checksum = Checksum;
	ProcNode->Pid = Pid;

end:
	// Return to the kernel address space
	KeDetachProcess();
	return Status;
}


/*
	Iterate every function imported by the current process
	and create a checksum out of all the imported functions
	which will be used to represent the process's IAT.
	Input:  BaseAddress - Process's image base address.
			pProcess - the EPROCESS struct of the process.
	Output: Whether the function was successful or not.
*/
INT64 GetIATChecksum(
	ULONG BaseAddress
)
{
	PIMAGE_IMPORT_DESCRIPTOR ImportTable = NULL;
	IMAGE_DATA_DIRECTORY ImportTableStruct;
	IMAGE_OPTIONAL_HEADER32 OptinalHeader;
	PIMAGE_NT_HEADERS32 PeHeaders = NULL;
	PIMAGE_DOS_HEADER DosHeader = NULL;
	INT64 Sum = 0, Checksum = 0;
	PCHAR DllName = { 0 };
	ULONG i = 0;

	__try {
		DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
		if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return FAILED;
	}
	__except(GetExceptionCode() == STATUS_ACCESS_VIOLATION ?
		EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		DbgPrint("[-] Exception occured at GetIATChecksum");
		return FAILED;
	}

	PeHeaders = (PIMAGE_NT_HEADERS32)(BaseAddress + DosHeader->e_lfanew);
	if (PeHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FAILED;

	OptinalHeader = PeHeaders->OptionalHeader;
	if (OptinalHeader.Magic != 0x10B)
		return FAILED;

	// Get the import table from the second entry of the data directory
	ImportTableStruct = OptinalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(ImportTableStruct.VirtualAddress + BaseAddress);

	if (!MmIsAddressValid(ImportTableStruct.VirtualAddress + BaseAddress))
	{
		DbgPrint("[-] Addresses are invalid \r\n");
		return FAILED;
	}

	// Going over every dll
	while (ImportTable[i].Characteristics != (ULONG)NULL)
	{
		DllName = (PCHAR)(ImportTable[i].Name + BaseAddress);
		if (DllName != NULL)
		{
			Sum = GetImportedFunctionsSum(
				ImportTable[i],
				BaseAddress
			);
			if (Sum == FAILED)
			{
				DbgPrint("[-] Failed to get imported functions of %s \r\n", DllName);
				return FAILED;
			}
			Checksum += Sum;
		}
		i++;
	}

	Checksum ^= (Checksum % 1000);
	Checksum += 0x92;

	return Checksum;
}


/*
	Get the sum of all imported functions for a
	given dll. This sum will later be used to
	calculate the checksum.
	Input:  Dll - the dll to be scanned.
			BaseAddress - the process' base address.
	Output: If successful - the checksum, otherwise -1.
*/
INT64 GetImportedFunctionsSum(
	IMAGE_IMPORT_DESCRIPTOR Dll,
	ULONG BaseAddress
)
{
	PIMAGE_IMPORT_BY_NAME FuncName = NULL;
	PIMAGE_THUNK_DATA32 ThunkILT = NULL;
	PIMAGE_THUNK_DATA32 ThunkIAT = NULL;
	ULONG ImportFunc;
	INT64 Sum = 0;

	ThunkILT = (PIMAGE_THUNK_DATA32)(Dll.OriginalFirstThunk);
	ThunkIAT = (PIMAGE_THUNK_DATA32)(Dll.FirstThunk);
	if (ThunkILT == NULL || ThunkIAT == NULL)
		return FAILED;

	ThunkILT = (PIMAGE_THUNK_DATA32)((ULONG)ThunkILT + BaseAddress);
	ThunkIAT = (PIMAGE_THUNK_DATA32)((ULONG)ThunkIAT + BaseAddress);
	if (ThunkILT == NULL || ThunkIAT == NULL)
		return FAILED;

	// going over every function in a specific dll
	while (ThunkILT->u1.AddressOfData != (ULONG)NULL)
	{
		if (ThunkILT->u1.Ordinal >= IMAGE_ORDINAL_FLAG)		// Address is at kernel space, might page fault!
		{
			return Sum;
		}

		FuncName = (PIMAGE_IMPORT_BY_NAME)(ThunkILT->u1.AddressOfData + BaseAddress);
		ImportFunc = ThunkIAT->u1.Function;

		Sum += ImportFunc;

		ThunkILT++;
		ThunkIAT++;
	}

	return Sum;
}


/*
	Add a new node to the linked list. Called whenever
	a new process was created.
	Input: The process' name, pid and checksum.
	Output: Whether the function was successful or not.
*/
NTSTATUS AddProcessToList(
	PNodeIAT NewNode
)
{
	PNodeIAT Temp = FirstNodeIAT;
	PNodeIAT PreTemp = Temp;

	// Adjust linked list
	if (FirstNodeIAT == NULL)
	{
		FirstNodeIAT = NewNode;
	}
	else
	{
		// Iterate the list to avoid duplicates
		while (Temp != NULL)
		{
			if (Temp->Pid == NewNode->Pid)	// Duplicate
			{
				return STATUS_ABANDONED;	// To free memory
			}
			PreTemp = Temp;
			Temp = Temp->Next;
		}

		PreTemp->Next = NewNode;
	}

	return STATUS_SUCCESS;
}


/*
	Remove a node from the linked list. Called whenever
	a process was deleted in the operating system.
	Input: The process pid.
	Output: Whether the function was successful or not.
*/
NTSTATUS RemoveProcessFromList(
	ULONG Pid
)
{
	PNodeIAT Temp = FirstNodeIAT;
	PNodeIAT PreTemp = Temp;

	while (Temp != NULL)
	{
		if (Temp->Pid == Pid)	// don't break in case there are duplicates
		{
			PreTemp->Next = Temp->Next;
			ExFreePool(Temp);
			Temp = PreTemp->Next;
		}
		else
		{
			PreTemp = Temp;
			Temp = Temp->Next;
		}
	}

	return STATUS_SUCCESS;
}


/*
	Write a buffer to an external file which will contain
	the results of the IAT scan. The results will be in
	the following format: 'IRP|<DEVICE_NAME>|<HOOKED_OR_NOT>'.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS WriteIatScanResults(HANDLE Handle)
{
	PNodeIAT Temp = FirstNodeIAT;
	IO_STATUS_BLOCK IoBlock;
	UNICODE_STRING uNum;
	PCHAR Buffer = NULL;
	ANSI_STRING aNum;
	NTSTATUS Status;

	// Allocate pool for future actions
	uNum.Buffer = (PWCH)ExAllocatePool(PagedPool, SIZE_OF_NUMBER);
	uNum.Length = uNum.MaximumLength = SIZE_OF_NUMBER;
	if (uNum.Buffer == NULL)
	{
		DbgPrint("[-] Failed to allocate memory \r\n");
		goto error;
	}

	// Zero memory
	RtlZeroMemory(uNum.Buffer, SIZE_OF_NUMBER);
	aNum.Buffer = NULL;

	while (Temp != NULL)
	{
		// Allocate buffer
		Buffer = (PCHAR)ExAllocatePool(PagedPool, LINE_SIZE);
		if (Buffer == NULL)
		{
			DbgPrint("[-] Failed to allocate memory \r\n");
			goto error;
		}
		RtlZeroMemory(Buffer, LINE_SIZE);

		// Copy 'IAT|' to the buffer
		Status = RtlStringCbCopyA(Buffer, LINE_SIZE, "IAT|");
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to copy a string \r\n");
			goto error;
		}

		// Concatenate the process name to the buffer
		Status = RtlStringCbCatA(Buffer, LINE_SIZE, Temp->ProcessName);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to concatenate a string \r\n");
			goto error;
		}

		// Concatenate '|' to the buffer
		Status = RtlStringCbCatA(Buffer, LINE_SIZE, "|");
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to concatenate a string \r\n");
			goto error;
		}

		// Convert the process id to unicode string
		Status = RtlIntegerToUnicodeString(Temp->Pid, DECIMAL, &uNum);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to convert integer to string \r\n");
			goto error;
		}

		// Convert the unicode string process id to ansi string
		Status = RtlUnicodeStringToAnsiString(&aNum, &uNum, TRUE);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to convert UNICODE string to ASCI string \r\n");
			goto error;
		}

		// Concatenate the process id to the buffer
		Status = RtlStringCbCatA(Buffer, LINE_SIZE, aNum.Buffer);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to concatenate a string \r\n");
			goto error;
		}
		ExFreePool(aNum.Buffer);

		// Concatenate whether the irp was hooked or not
		if (Temp->IsHooked == TRUE)
			Status = RtlStringCbCatA(Buffer, LINE_SIZE, "|1\n");
		else
			Status = RtlStringCbCatA(Buffer, LINE_SIZE, "|0\n");
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

	ExFreePool(uNum.Buffer);
	return STATUS_SUCCESS;

error:
	if (uNum.Buffer != NULL)
		ExFreePool(uNum.Buffer);
	if (aNum.Buffer != NULL)
		ExFreePool(aNum.Buffer);
	if (Buffer != NULL)
		ExFreePool(Buffer);
	return STATUS_UNSUCCESSFUL;
}