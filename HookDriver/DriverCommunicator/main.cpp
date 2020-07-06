#include <stdio.h>
#include <Windows.h>

//#define SIOCTL_TYPE 40000
//#define IOCTL_SSDT\
// CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_SSDT 1
#define IOCTL_IRP 2
#define IOCTL_IDT 3
#define IOCTL_UNHOOK 4

int main(void)
{
	HANDLE hDevice;

	// Starting drivers
	
	// Register driver (write it to the registery)
	system("sc create HookDriver binpath= c:\\windows\\system32\\drivers\\HookDriver.sys type= kernel start= demand");

	// Load driver to the kernel and start its service
	system("sc start HookDriver");

	// Register driver (write it to the registery)
	system("sc create VictimDriver binpath= c:\\windows\\system32\\drivers\\VictimDriver.sys type= kernel start= demand");

	// Load driver to the kernel and start its service
	system("sc start VictimDriver");


	// Get handle to the drivers symbolic link
	hDevice = CreateFileA(
		"\\\\.\\HookDriver",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL
	);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to get device handle \r\n");
		return 1;
	}
	printf("[+] Got driver handle \r\n");

	// Send an ioctl SSDT to the driver, making him execute the SSDT hook
	printf("[+] Hooking the ZwQuerySystemInformation entry in the SSDT \r\n");
	DeviceIoControl(
		hDevice,
		IOCTL_SSDT,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	getchar();
	getchar();

	// Send an ioctl IRP to the driver, making him execute the IRP hook
	printf("[+] Hooking the CREATE IRP in the victim driver \r\n");
	DeviceIoControl(
		hDevice,
		IOCTL_IRP,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	getchar();
	getchar();

	// unhook
	printf("[+] Releasing hooks \r\n");
	DeviceIoControl(
		hDevice,
		IOCTL_UNHOOK,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	CloseHandle(hDevice);
	system("pause");
	return 0;
}