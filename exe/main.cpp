#include <Windows.h>
#include <stdio.h>
#include <intrin.h>
#include "..\CustomSyscall\shared.h"

extern "C" ULONG sysp( void );


int main( void )
{
    SC_HANDLE hService = nullptr;
    SC_HANDLE hSCManager = OpenSCManagerW( nullptr, nullptr, SC_MANAGER_CREATE_SERVICE );

    if ( hSCManager ) {

        wchar_t fpath[_MAX_PATH];
        GetCurrentDirectoryW( sizeof( fpath ) / 2, fpath );
        lstrcatW( fpath, L"\\CustomSyscall.sys" );
        hService = CreateServiceW( hSCManager, L"CustomSyscall", L"CustomSyscall Driver", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, fpath, nullptr, nullptr, nullptr, nullptr, nullptr );

        if ( !hService ) {

            printf( "[-] CreateServiceW: %d\n", GetLastError() );
			hService = OpenService( hSCManager, L"CustomSyscall", SERVICE_START | DELETE | SERVICE_STOP );
        
        }

        if ( StartServiceW( hService, 0, nullptr ) ) {
            HANDLE hFile = CreateFileW( L"\\\\.\\CustomSyscall", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr );

            if ( hFile ) {
                
                DeviceIoControl( hFile, IOCTL_INSTALL_CS, nullptr, 0, nullptr, 0, nullptr, nullptr );

            }

        } else {
        
            printf( "[-] StartServiceW: %d\n", GetLastError() );
        
        }

    
    } else {
    
        printf( "[-] OpenSCManagerW: %d\n", GetLastError() );

    }


    printf( "[!] Press ENTER to break\n" );
    getchar();
    __debugbreak();
    sysp();

    // printf( "[!] Press ENTER to Stop Service\n" );
    // getchar();

    SERVICE_STATUS ssp;
    ControlService( hService, SERVICE_CONTROL_STOP, &ssp );
    DeleteService( hService );
    CloseServiceHandle( hSCManager );

    return 0;
}
