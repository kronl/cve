# Privilege Escalation in MSI Dragon Center

## Information
- **Disclosure**: 09 December 2020
- **Product**: MSI Dragon Center
- **Affected Version**: 2.0.87.0
- **Patched Version:** 2.0.98.0
- **Offitial Website:** [https://www.msi.com](https://www.msi.com/index.php)

## Description
MSI Dragon Center is designed to manage universal drivers for MSI laptops. It can monitor and
optimize the system performance of all MSI devices. This software is required whenever they need a
gaming feature on their devices or on mandatory driver update. According to the description page, it supports about 80 different MSI laptop models.
When the software is installed, a driver named MsIo64.sys is loaded and started as a Windows service. It is used to manage I/O ports inside the Windows kernel. Therefore, abusing this driver could lead an attacker to conduct malicious activities at a privileged level.
We found an improper usage of dangerous function which would trigger multiple stack buffer overflow inside the driver. This vulnerability could be exploited by attackers for privilege escalation and code execution under high privileges. Exploit code for this is able to take a form of any ordinary program, thereby could easily be executed on the victim host and perform destructive operations.

## Root cause analysis
Inside the dispatcher routine which is responsible for DeviceIoControl requests, the code below handles requests with the IoControlCode (IOCTL) 0x80102040, 0x80102044, 0x80102050,and 0x80102054. But there is also no sign of boundary check or mitigations.
There is a use of `memmove` function whose `dst` is within the function frame, yet `Src` and `len` are user controlled.
```c
case 0x80102040: //same as 0x80102044
	if ( !inBufferSize )
		goto LABEL_9;
	memmove(&Src, systemBuffer, inBufferSize);
	status = sub_11090(v16, Src, &BaseAddress, &Handle, &Object)
	if ( status >= 0 )
	{
		memmove(systemBuffer, &Src, inBufferSize);
		irp->IoStatus.Information = inBufferSize;
	}
	irp->IoStatus.Status = status;
	break;
```

There is a use of `memmove` function whose `dst` is within the function frame, yet `Dst` and `len` are user controlled.
```c
case 0x80102050: //same as 0x80102054
	if ( !inBufferSize )
		goto LABEL_9;
	memmove(&Dst, systemBuffer, inBufferSize);
	if ( v22 == 1)
	{
		v10 = _inbyte(Dst);
		*systemBuffer = v10;
		v2->IoStatus.Information = 4i64;
	}
```
These code allow a malicious user to abuse the frame with a crafted payload and trigger buffer overflow after all. We conducted an experiment with an 80byte buffer and could overwrite return address to arbitrary value as below.

## Report Timeline
- 2020-12-09 : First contact with MSI attempted through the website form
- 2021-01-10 : Relese patched version through the Microsoft Store
- 2021-03-04 : Request CVE ID to Mitre