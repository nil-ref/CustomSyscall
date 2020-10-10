#pragma once

#define NT_DEVICE_NAME          L"\\Device\\CustomSyscall"
#define DOS_DEVICE_NAME         L"\\DosDevices\\CustomSyscall"
#define WIN32_DEVICE_NAMEW      L"\\\\.\\CustomSyscall"
#define WIN32_DEVICE_NAMEA      "\\\\.\\CustomSyscall"


#define IOCTL_INSTALL_CS CTL_CODE( FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_SPECIAL_ACCESS )

