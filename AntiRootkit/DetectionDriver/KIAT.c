#include "KIAT.h"
#include "IAT.h"

#define FAILED (ULONG)(-1)
#define LINE_SIZE 9		//KIAT|<ModuleName>|0\n

// Globals
PNodeKIAT FirstNodeKIAT;	// modules linked list


/*
	Init the variables required for the kernel IAT scan.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS InitVarsKIAT()
{
	FirstNodeKIAT = NULL;

	return STATUS_SUCCESS;
}


/*
	Unload the kernel IAT scanner, free all the resources.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS UnloadKIAT()
{
	PNodeKIAT Temp;

	// Free linked list
	while (FirstNodeKIAT != NULL)
	{
		Temp = FirstNodeKIAT;
		FirstNodeKIAT = FirstNodeKIAT->Next;

		ExFreePool(Temp->ModuleName);
		ExFreePool(Temp);
	}

	return STATUS_SUCCESS;
}


/*
	Scan the IAT tables of the known kernel modules which
	are located at the linked list. If there is a checksum
	mismatch, an IAT hook occured. If a module is invalid,
	for example a non paged based address, remove it 
	from the list and free its memory.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS ScanKIAT()
{
	NTSTATUS Status = STATUS_SUCCESS;
	PNodeKIAT Temp = FirstNodeKIAT;
	PNodeKIAT Node = NULL;
	PCHAR TempName = 0;

	Node = ExAllocatePool(PagedPool, sizeof(NodeKIAT));
	if (Node == NULL)
	{
		DbgPrint("[-] Failed to allocate memory for module \r\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(Node, sizeof(NodeKIAT));

	// Iterate the linked list
	while (Temp != NULL)
	{
		Status = ScanModuleIAT(Temp->ModuleName, Temp->BaseAddress, Node);
		if (Status == STATUS_ABANDONED)
		{
			DbgPrint("[-] Module '%s' couldn't be accessed \r\n", Temp->ModuleName);

			// To avoid use-after-free
			TempName = Temp->ModuleName;
			Temp = Temp->Next;
			RtlZeroMemory(Node, sizeof(NodeKIAT));	// for the next loop

			RemoveModuleFromList(TempName);
			continue;
		}
		else if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to scan module '%s' IAT \r\n", Temp->ModuleName);
		}
		else
		{
			if (Node->Checksum != Temp->Checksum)
			{
				DbgPrint("[***] Found IAT Hook at module '%s' \r\n", Temp->ModuleName);
				Temp->IsHooked = TRUE;
			}
		}

		Temp = Temp->Next;
		RtlZeroMemory(Node, sizeof(NodeKIAT));
	}

	ExFreePool(Node);
	return STATUS_SUCCESS;
}


NTSTATUS AddNewKernelModule(
	PCHAR ModuleName,
	ULONG ModuleBase
)
{
	// This will be used to add a new kernel module to the linked list
	// and to scan it everytime a scan is to be made.

	// The modules will have different struct, without PID, which means
	// they'll have their own linked list.
	// When printing them, they will be IAT-K|, and in the GUI they
	// will have their own tab for IAT - Kernel

	// In the Driver entry we will initalize array of PAUX_..., and in
	// the device ioctl this function will be called for every element 
	// in this list.

	// The scan will also check the kernel module linked list!

	PNodeKIAT NewNode = NULL;
	NTSTATUS Status;

	// Check is module already present in the linked list
	if (IsModuleInLinkedList(ModuleName))
	{
		DbgPrint("[+] Module was already added, no need to perform function \r\n");
		return STATUS_SUCCESS;
	}

	// Allocate a new node to be used and zero its memory.
	NewNode = ExAllocatePool(PagedPool, sizeof(NodeKIAT));
	if (NewNode == NULL)
	{
		DbgPrint("[-] Failed to allocate memory for new module \r\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(NewNode, sizeof(NodeKIAT));

	// Set the new node values by iterating the current module IAT.
	Status = ScanModuleIAT(ModuleName, ModuleBase, NewNode);
	if (!NT_SUCCESS(Status) || Status == STATUS_ABANDONED)
	{
		DbgPrint("[-] Failed to scan new module \r\n");
		goto free;
	}

	// If all went well, insert the new node to the linked list of open modules.
	Status = AddModuleToList(NewNode);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[-] Failed to add new module to the linked list \r\n");
		goto free;
	}
	else if (Status == STATUS_ABANDONED)
	{
		DbgPrint("[-] New module was a duplicate \r\n");
		goto free;
	}

	return STATUS_SUCCESS;

free:
	if(NewNode->ModuleName != NULL)
		ExFreePool(NewNode->ModuleName);
	if (NewNode != NULL)
		ExFreePool(NewNode);

	return STATUS_UNSUCCESSFUL;
}


/*
	Helper function. Scan the IAT of a given kernel module
	and return its node structure filled. Will be called
	by the AddNewKernelModule function and ScanIAT function.
	Input:  Name - the name of the kernel module.
			BaseAddress - the base address of the module.
			ModuleNode - a pointer to an allocated node.
	Output: Whether the function was successful or not.
*/
NTSTATUS ScanModuleIAT(
	PCHAR Name,
	ULONG BaseAddress,
	PNodeKIAT ModuleNode
)
{
	INT64 Checksum = 0;

	// Node was not initialized
	if (ModuleNode == NULL || Name == NULL)
		return STATUS_UNSUCCESSFUL;

	// The module is invalid, base address points to a non paged memory
	if (BaseAddress == (ULONG)NULL || !MmIsAddressValid((PVOID)BaseAddress))
		return STATUS_ABANDONED;

	Checksum = GetIATChecksum(BaseAddress);
	if (Checksum == FAILED)
	{
		DbgPrint("[-] Failed to scan the IAT for module %s \r\n", Name);
		return STATUS_ABANDONED;
	}

	// Setting values for the new node. The rest are zeroed (NULL/FALSE).
	ModuleNode->ModuleName = ExAllocatePool(PagedPool, strlen(Name) * sizeof(CHAR) + 1);
	if (ModuleNode->ModuleName == NULL ||
		RtlStringCbCopyA(ModuleNode->ModuleName, strlen(Name) * sizeof(CHAR) + 1, Name))
		return STATUS_UNSUCCESSFUL;
	
	//ModuleNode->ModuleName = Name;			// Maybe Name is already allocated from the aux list?
	ModuleNode->BaseAddress = BaseAddress;
	ModuleNode->Checksum = Checksum;

	return STATUS_SUCCESS;
}


NTSTATUS AddModuleToList(
	PNodeKIAT NewNode
)
{
	PNodeKIAT Temp = FirstNodeKIAT;
	PNodeKIAT PreTemp = Temp;

	// Adjust linked list
	if (FirstNodeKIAT == NULL)
	{
		FirstNodeKIAT = NewNode;
	}
	else
	{
		if (IsModuleInLinkedList(NewNode->ModuleName))
			return STATUS_ABANDONED;

		// Get to the end of the linked list
		while (Temp != NULL)
		{
			PreTemp = Temp;
			Temp = Temp->Next;
		}

		PreTemp->Next = NewNode;
	}

	return STATUS_SUCCESS;
}


NTSTATUS RemoveModuleFromList(
	PCHAR Name
)
{
	PNodeKIAT PreTemp = FirstNodeKIAT;
	PNodeKIAT Temp = FirstNodeKIAT;

	// Iterate linked list
	while (Temp != NULL)
	{
		if (strcmp(Name, Temp->ModuleName) == 0)	// don't break in case there are duplicates
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
	Check if the given module name is in the linked list.
	Input:  Name - the name of the module to be searched.
	Output: whether the given module is in the list or not.
*/
BOOLEAN IsModuleInLinkedList(
	PCHAR Name
)
{
	// Iterate the linked list and search for the given name
	PNodeKIAT Temp = FirstNodeKIAT;
	
	while (Temp != NULL)
	{
		if (strcmp(Name, Temp->ModuleName) == 0)
		{
			return TRUE;
		}
		Temp = Temp->Next;
	}
	
	return FALSE;
}


NTSTATUS WriteKernelIatScanResults(HANDLE Handle)
{
	PNodeKIAT Temp = FirstNodeKIAT;
	IO_STATUS_BLOCK IoBlock;
	PCHAR Buffer = NULL;
	ULONG BufferSize;
	NTSTATUS Status;

	while (Temp != NULL)
	{
		// Allocate buffer according to name size
		BufferSize = LINE_SIZE + strlen(Temp->ModuleName);
		Buffer = (PCHAR)ExAllocatePool(PagedPool, BufferSize);
		if (Buffer == NULL)
		{
			DbgPrint("[-] Failed to allocate memory \r\n");
			goto error;
		}
		RtlZeroMemory(Buffer, BufferSize);

		// Copy 'KIAT|' to the buffer
		Status = RtlStringCbCopyA(Buffer, BufferSize, "KIAT|");
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to copy a string \r\n");
			goto error;
		}

		// Concatenate the module name to the buffer
		Status = RtlStringCbCatA(Buffer, BufferSize, Temp->ModuleName);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to concatenate a string \r\n");
			goto error;
		}

		// Concatenate whether the iat was hooked or not
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
		Buffer = NULL;

		Temp = Temp->Next;
	}

	return STATUS_SUCCESS;

error:
	if (Buffer != NULL)
		ExFreePool(Buffer);

	return STATUS_UNSUCCESSFUL;
}