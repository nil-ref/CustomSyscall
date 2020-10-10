#include <ntifs.h>
#include <intrin.h>
#include "shared.h"

#define SSDT_OFFSET( base, func ) ( (ULONG)(((uintptr_t)func - (uintptr_t)base) << 4 ) )

extern "C" {
    NTKERNELAPI bool NTAPI KeAddSystemServiceTable( PULONG Base, PULONG Count, ULONG Limit, PUCHAR Number, ULONG Index );
    NTKERNELAPI bool NTAPI KeRemoveSystemServiceTable( unsigned int Index );
    NTKERNELAPI ULONG PsGetProcessSessionId( PEPROCESS Process );
    NTKERNELAPI ULONG PsGetProcessSessionIdEx( PEPROCESS Process );
    }

extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;





typedef ULONG SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;
typedef struct _KSERVICE_DESCRIPTOR_TABLE {
    PSYSTEM_SERVICE_TABLE ServiceTableBase;             // pointer to the base of the SSDT
    PSYSTEM_SERVICE_TABLE ServiceCounterTableBase;      // ???
    ULONG NumberOfServices;                             // number of services in SSDT
    PUCHAR ParamTableBase;                              // table for number of bytes arguments take on the stack -- TODO
} KSERVICE_DESCRIPTOR_TABLE, *PKSERVICE_DESCRIPTOR_TABLE;

SYSTEM_SERVICE_TABLE ServiceTableBase[1];
UCHAR ParamTableBase[1];


//
//
//
VOID DriverUnload( PDRIVER_OBJECT DriverObject )
{
    KdPrint( ( "=== %s: Goodbye World!\n", __FUNCTION__ ) );
    UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING( DOS_DEVICE_NAME );
    IoDeleteSymbolicLink( &dosDeviceName );
    IoDeleteDevice( DriverObject->DeviceObject );
}


//
//
//
NTSTATUS IrpDefaultHandler( PDEVICE_OBJECT DeviceObject, PIRP Irp )
{
    UNREFERENCED_PARAMETER( DeviceObject );

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}

//
//
//
NTSTATUS MyCustomSyscall( VOID )
{
    DbgPrint( "Hello World!\n" );
    return STATUS_SUCCESS;
}


#if 0
TOOD: REMOVE ME
//
//
//
NTSTATUS InstallSyscall( VOID )
{
    PUCHAR pStartAddress = (PUCHAR)__readmsr( 0xC0000082 ); // MSR's kernel's RIP SYSCALL entry for 64 bit
    KdPrint( ( "=== pStart: %p\n", pStartAddress ) );

    for ( int i = 0; i < 1024; i++ ) {
        
        if ( pStartAddress[i] == 0x4c && pStartAddress[i + 1] == 0x8d && pStartAddress[i + 7] == 0x4c && pStartAddress[i + 8] == 0x8d && pStartAddress[i + 14] == 0xf7 && pStartAddress[i + 15] == 0x43 ) {
            // 4C 8D 15 E5 8D 3B 00    lea     r10, KeServiceDescriptorTable
            // 4C 8D 1D DE 0F 3A 00    lea     r11, KeServiceDescriptorTableShadow
            // F7 43 78 80 00 00 00    test    dword ptr [rbx+78h], 80h

            ssdt = (SSDT*)( pStartAddress + *(int*)&pStartAddress[2] + 7 );
            KdPrint( ( "=== ssdt: %p\n", ssdt ) );
            return STATUS_SUCCESS;
        }

    }


    return STATUS_UNSUCCESSFUL;
}
#endif

PEPROCESS FindProcessWithSessIdZero( VOID )
{
    for ( ULONG i = 4; i <= HandleToUlong(PsGetCurrentProcessId()); i += 4 ) {
        PEPROCESS eProc = nullptr;
        NTSTATUS ntStatus = PsLookupProcessByProcessId( UlongToHandle( i ), &eProc );

        if ( NT_SUCCESS( ntStatus ) && eProc ) {
            
            if ( PsGetProcessSessionIdEx( eProc ) == 0 ) {
                return eProc;            
            }
            ObDereferenceObject( eProc );

        }


    }

    return nullptr;
}

//
//
//
NTSTATUS InstallServiceTable( VOID )
{
    PEPROCESS eProc = FindProcessWithSessIdZero();
    if ( eProc == nullptr ) {
        KdPrint( ( "[-] %s: Failed to find a process with SessionId == 0\n", __FUNCTION__ ) );
        return STATUS_UNSUCCESSFUL;
    }

    ServiceTableBase[0] = SSDT_OFFSET( ServiceTableBase, MyCustomSyscall );

    KAPC_STATE ApcState;

    KeStackAttachProcess( eProc, &ApcState );
    bool ntRet = KeRemoveSystemServiceTable( 2 );
    KeUnstackDetachProcess( &ApcState );
    ObDereferenceObject( eProc );

    KdPrint( ( "=== KeAddSystemServiceTable: %#x\n", ntRet ) );

    ntRet = KeAddSystemServiceTable( ServiceTableBase, nullptr, ARRAYSIZE( ServiceTableBase ), ParamTableBase, 2 );
    KdPrint( ( "=== ServiceTableBase: %p\n", ServiceTableBase ) );
    KdPrint( ( "=== KeAddSystemServiceTable: %#x\n", ntRet ) );
    
    return STATUS_UNSUCCESSFUL;
}


NTSTATUS IrpDeviceIoHandler( PDEVICE_OBJECT DevObj, PIRP Irp )
{
    UNREFERENCED_PARAMETER( DevObj );

    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation( Irp );

    Irp->IoStatus.Information = 0;

    if ( IrpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_INSTALL_CS ) {
        Irp->IoStatus.Status = InstallServiceTable();        
    }

    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return STATUS_SUCCESS;
}

//
//
//
extern "C" NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath )
{
    UNREFERENCED_PARAMETER( RegistryPath );

    UNICODE_STRING ntDeviceName = RTL_CONSTANT_STRING( NT_DEVICE_NAME );
    PDEVICE_OBJECT DeviceObject;

    NTSTATUS ntStatus = IoCreateDevice( DriverObject, 0, &ntDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject );

    if ( !NT_SUCCESS( ntStatus ) ) {
        return ntStatus;
    }

    for ( int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++ ) {
        DriverObject->MajorFunction[i] = IrpDefaultHandler;
    }
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoHandler;
    DriverObject->DriverUnload = DriverUnload;

    UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING( DOS_DEVICE_NAME );
    IoDeleteSymbolicLink( &dosDeviceName );
    ntStatus = IoCreateSymbolicLink( &dosDeviceName, &ntDeviceName );

    if ( !NT_SUCCESS( ntStatus ) ) {
        IoDeleteDevice( DeviceObject );
    }

    return ntStatus;
}

