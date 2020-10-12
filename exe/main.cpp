#include <Windows.h>
#include <stdio.h>
#include <intrin.h>
#include "..\CustomSyscall\shared.h"
#include <cstdio>
#include <string>
#include <errno.h>

extern "C" LONG sysp( void );


void print_help( const char* name )
{
    printf( "Usage: %s <OPTION>\n"
            "Options:\n"
            "    help       Print this message.\n"
            "    install    Load Driver\n"
            "    uninstall  Unload Driver\n"
            "    syscall    Issue the custom syscall\n", name );
}

std::string perr( LONG errn = 0 )
{
    DWORD errorMessageID = errn ? errn : GetLastError();
    if ( errorMessageID == 0 ) {
        return std::string( "STATUS_SUCCESS" );
    }

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      errorMessageID,
      MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
      (LPSTR)&messageBuffer,
      0,
      NULL );

    std::string message( messageBuffer, size );

    LocalFree( messageBuffer );

    return message;
}

int install( void )
{
    SC_HANDLE hService = nullptr;
    SC_HANDLE hSCManager = OpenSCManagerW( nullptr, nullptr, SC_MANAGER_CREATE_SERVICE );

    if ( hSCManager ) {
        wchar_t fpath[_MAX_PATH];
        GetCurrentDirectoryW( sizeof( fpath ) / 2, fpath );
        lstrcatW( fpath, L"\\CustomSyscall.sys" );
        hService = CreateServiceW( hSCManager, L"CustomSyscall", L"CustomSyscall Driver", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, fpath, nullptr, nullptr, nullptr, nullptr, nullptr );

        if ( !hService ) {
            CloseServiceHandle( hSCManager );
            printf( "[-] CreateServiceW: %s\n", perr().c_str() );
            return 1;
        }

        if ( !StartServiceW( hService, 0, nullptr ) ) {
            printf( "[-] StartServiceW: %s\n", perr().c_str() );
            CloseServiceHandle( hService );
            CloseServiceHandle( hSCManager );
            return 1;
        }

        CloseServiceHandle( hSCManager );
        CloseServiceHandle( hService );
        return ERROR_SUCCESS;

    }

    printf( "[-] OpenSCManagerW: %s\n", perr().c_str() );
    return 1;
}


int uninstall( void )
{
    SC_HANDLE hService = nullptr;
    SC_HANDLE hSCManager = OpenSCManagerW( nullptr, nullptr, SC_MANAGER_CREATE_SERVICE );

    if ( hSCManager ) {
        hService = hService = OpenService( hSCManager, L"CustomSyscall", SERVICE_START | DELETE | SERVICE_STOP );

        if ( !hService ) {
            printf( "[-] OpenService: %s\n", perr().c_str() );
            CloseServiceHandle( hSCManager );
            return 1;
        }

        SERVICE_STATUS ssp;
        ControlService( hService, SERVICE_CONTROL_STOP, &ssp );
        DeleteService( hService );
        CloseServiceHandle( hSCManager );
        CloseServiceHandle( hService );
        return ERROR_SUCCESS;
    }

    printf( "[-] OpenSCManagerW: %s\n", perr().c_str() );
    return 1;
}

int main( int argc, char** argv )
{
    if ( argc != 2 ) {
        print_help( argv[0] );
        return 1;
    }

    if ( !_stricmp( argv[1], "help" ) ) {

        print_help( argv[0] );

    } else if ( !_stricmp( argv[1], "install" ) ) {

        return install();
    
    } else if ( !_stricmp( argv[1], "uninstall" ) ) {

        return uninstall();

    } else if ( !_stricmp( argv[1], "syscall" ) ) {

        printf( "[!] %s\n", perr( sysp() ).c_str() );

    } else {

        print_help( argv[0] );
        return 1;

    }

    return 0;

}
