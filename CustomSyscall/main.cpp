#include <ntifs.h>
#include <intrin.h>
#include "shared.h"
#include "PE.h"

#define SSDT_OFFSET( base, func ) ( (LONG)(((uintptr_t)func - (uintptr_t)base) << 4 ) )

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks; //0x0
    VOID* ExceptionTable; //0x10
    ULONG ExceptionTableSize; //0x18
    VOID* GpValue; //0x20
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo; //0x28
    VOID* DllBase; //0x30
    VOID* EntryPoint; //0x38
    ULONG SizeOfImage; //0x40
    UNICODE_STRING FullDllName; //0x48
    UNICODE_STRING BaseDllName; //0x58
    ULONG Flags; //0x68
    USHORT LoadCount; //0x6c
    union {
        USHORT SignatureLevel : 4; //0x6e
        USHORT SignatureType : 3; //0x6e
        USHORT Unused : 9; //0x6e
        USHORT EntireField; //0x6e
    } u1; //0x6e
    VOID* SectionPointer; //0x70
    ULONG CheckSum; //0x78
    ULONG CoverageSectionSize; //0x7c
    VOID* CoverageSection; //0x80
    VOID* LoadedImports; //0x88
    VOID* Spare; //0x90
    ULONG SizeOfImageNotRounded; //0x98
    ULONG TimeDateStamp; //0x9c
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef LONG SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;
typedef struct _KSERVICE_DESCRIPTOR_TABLE {
    PSYSTEM_SERVICE_TABLE ServiceTableBase;             // pointer to the base of the SSDT
    PSYSTEM_SERVICE_TABLE ServiceCounterTableBase;      // ???
    ULONG NumberOfServices;                             // number of services in SSDT
    PUCHAR ParamTableBase;                              // table for number of bytes arguments take on the stack -- TODO
} KSERVICE_DESCRIPTOR_TABLE, *PKSERVICE_DESCRIPTOR_TABLE;


EXTERN_C NTKERNELAPI LIST_ENTRY PsLoadedModuleList;


//
// Saved Globals
//
ULONG origNumberOfServices;
UCHAR origTrampolineBytes[12];
PUCHAR trampoline;
PKSERVICE_DESCRIPTOR_TABLE ssdt;

//
//
//
VOID DriverUnload( PDRIVER_OBJECT DriverObject )
{
    ssdt->NumberOfServices = origNumberOfServices;
    RtlCopyMemory( trampoline, origTrampolineBytes, 12 );
    IoDeleteDevice( DriverObject->DeviceObject );

    KdPrint(( "-- [!] -- CustomSyscall Unloaded\n" ));
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
    KdPrint(( "-- [!] -- Hello from %s!\n", __FUNCTION__ ));
    return STATUS_SUCCESS;
}

//
//
//
PUCHAR findTrampoline( VOID )
{
    PUCHAR addr = (PUCHAR)__readmsr( 0xC0000082 ); // KiSystemCall64 or KiSystemCall64Shadow depending on Win version

    for ( int i = 0; i < 0x2000; i++ ) {
        
        if ( RtlCompareMemory( &addr[i], "\x66\x66\x66\x66\x66\x66\x66\x0f\x1f\x84\x00\x00", 12 ) == 12 ) {
            return &addr[i];
        }

        if ( RtlCompareMemory( &addr[i], "\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc", 12 ) == 12 ) {
            return &addr[i];
        }

    }

    return nullptr;
}

//
//
//
PKSERVICE_DESCRIPTOR_TABLE getKeServiceDescriptorTable( bool Shadow = false )
{
    PKSERVICE_DESCRIPTOR_TABLE result = nullptr;

    PEHeader nt( ((PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList.Flink)->DllBase );

    PIMAGE_SECTION_HEADER shdr = nt.section_hdr( ".text" );
    if ( shdr == nullptr ) {
        KdPrint( ( "-- [-] -- .text section NOT FOUND\n" ) );
        return nullptr;
    }

    PUCHAR pStartAddress = (PUCHAR)nt.rva2va( shdr->VirtualAddress );
    KdPrint(( "-- [!] -- Searching %p for SSDT in %#x bytes.\n", pStartAddress, shdr->Misc.VirtualSize ));

    for ( ULONG i = 0; i < shdr->Misc.VirtualSize; i++ ) {

        if ( pStartAddress[i] == 0x4c && pStartAddress[i + 1] == 0x8d && pStartAddress[i + 2] == 0x15 &&
             pStartAddress[i + 7] == 0x4c && pStartAddress[i + 8] == 0x8d && pStartAddress[i + 9] == 0x1d &&
             pStartAddress[i + 14] == 0xf7 && pStartAddress[i + 15] == 0x43 ) {

            // 4C 8D 15 E5 8D 3B 00    lea     r10, KeServiceDescriptorTable
            // 4C 8D 1D DE 0F 3A 00    lea     r11, KeServiceDescriptorTableShadow
            // F7 43 78 80 00 00 00    test    dword ptr [rbx+78h], 80h

            if ( Shadow ) {
                result = ( PKSERVICE_DESCRIPTOR_TABLE )( &pStartAddress[i + 7] + *(int*)&pStartAddress[i + 7 + 3] + 7 );
            } else {
                result = ( PKSERVICE_DESCRIPTOR_TABLE )( &pStartAddress[i] + *(int*)&pStartAddress[i + 3] + 7 );
            }

            if ( MmIsAddressValid( result ) && MmIsAddressValid( result->ServiceTableBase ) ) {
                KdPrint(( "-- [+] -- SSDT: %p\n", result ));
                KdPrint(( "-- [+] -- SST : %p\n", result->ServiceTableBase ));
                return result;
            }
        }
    
    }

    return nullptr;
}

//
// Check if we can safely overflow Out of Bounds of ssdt->ServiceTableBase
//
bool SyscallIsOverMin( USHORT sysnum, PKSERVICE_DESCRIPTOR_TABLE pssdt )
{
    KdPrint(( "-- [!] -- sysnum: %#x, count: %#x\n", sysnum, ssdt->NumberOfServices ));

    if ( sysnum < pssdt->NumberOfServices ) {
        return false;
    }

    // This verifies that ParamTable is located after the ServiceTableBase
    //
    if ( (uintptr_t)pssdt->ParamTableBase - (uintptr_t)&pssdt->ServiceTableBase[pssdt->NumberOfServices] <= 0x20 /* -+ 0x20 */) {
        
        uintptr_t min = (uintptr_t)&pssdt->ParamTableBase[pssdt->NumberOfServices] - (uintptr_t)pssdt->ServiceTableBase;
        min += 0x100;   // Arbitrary value
        min &= ~0xf;
        min >>= 2;

        KdPrint(( "-- [!] -- Min syscall number is %#x\n", (USHORT)min ));

        return sysnum >= min;

    } else {

        KdPrint(( "-- [!] -- ParamTableBase was not located following the ServiceTableBase. Need to inspect manually if table can be OOB\n" ));
    
    }


    return true;
}

//
//
//
NTSTATUS InstallSyscall( USHORT sysnum, void* func )
{
    if ( sysnum > 0xFFF || !MmIsAddressValid( func ) ) {
        return STATUS_INVALID_PARAMETER;
    }

    ssdt = getKeServiceDescriptorTable();
    trampoline = findTrampoline();

    if ( !ssdt || !trampoline ) {
        return STATUS_UNSUCCESSFUL;
    }

    if ( !SyscallIsOverMin( sysnum, ssdt ) ) {
        return STATUS_INVALID_PARAMETER;
    }

    // Save globals
    //
    RtlCopyMemory( origTrampolineBytes, trampoline, 12 );
    origNumberOfServices = ssdt->NumberOfServices;

    // Install trampoline
    //
    trampoline[0] = 0x48;
    trampoline[1] = 0xb8;
    *(size_t*)&trampoline[2] = (size_t)func;
    trampoline[10] = 0xff;
    trampoline[11] = 0xe0;

    // Inject syscall entry
    //
    LONG offset = SSDT_OFFSET( ssdt->ServiceTableBase, trampoline );
    ssdt->ServiceTableBase[sysnum] = offset;
    ssdt->NumberOfServices = sysnum + 1;


    return STATUS_SUCCESS;
}


//
//
//
EXTERN_C NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath )
{
    UNREFERENCED_PARAMETER( RegistryPath );

    UNICODE_STRING ntDeviceName = RTL_CONSTANT_STRING( NT_DEVICE_NAME );
    PDEVICE_OBJECT DeviceObject;

    NTSTATUS ntStatus = IoCreateDevice( DriverObject, 0, &ntDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject );

    if ( !NT_SUCCESS( ntStatus ) ) {
        return ntStatus;
    }

    if ( !NT_SUCCESS( InstallSyscall( 0x321, MyCustomSyscall ) ) ) {
        IoDeleteDevice( DeviceObject );
        return STATUS_UNSUCCESSFUL;
    }

    for ( int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++ ) {
        DriverObject->MajorFunction[i] = IrpDefaultHandler;
    }
    DriverObject->DriverUnload = DriverUnload;

    KdPrint(( "-- [+] -- Successful injection.\n" ));

    return ntStatus;
}

