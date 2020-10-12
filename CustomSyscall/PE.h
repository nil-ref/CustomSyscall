#pragma once
#include <ntifs.h>
#include <ntimage.h>

class PEHeader
{
protected:
    void* base;

public:
    PEHeader( void* addr )
        : base( addr )
    {
    }

    void* get_base( void )
    {
        return base;
    }

    void* rva2va( size_t rva )
    {
        return reinterpret_cast< char* >( base ) + rva;
    }

    PIMAGE_DOS_HEADER pe_hdr( void )
    {
        return reinterpret_cast< PIMAGE_DOS_HEADER >( base );
    }

    PIMAGE_NT_HEADERS64 nt_hdr( void )
    {
        return reinterpret_cast< PIMAGE_NT_HEADERS64 >( reinterpret_cast< size_t >( base ) + pe_hdr()->e_lfanew );
    }

    PIMAGE_FILE_HEADER file_hdr( void )
    {
        return &nt_hdr()->FileHeader;
    }

    PIMAGE_OPTIONAL_HEADER optional_hdr( void )
    {
        return &nt_hdr()->OptionalHeader;
    }

    PIMAGE_DATA_DIRECTORY data_dir( size_t index )
    {
        return &optional_hdr()->DataDirectory[index];
    }

    PIMAGE_SECTION_HEADER section_hdr( unsigned int index )
    {
        return IMAGE_FIRST_SECTION( nt_hdr() ) + index;
    }

    PIMAGE_SECTION_HEADER section_hdr( const char* sname )
    {
        for ( int i = 0; i < file_hdr()->NumberOfSections; i++ ) {
            auto section = section_hdr( i );
            const char* s1 = sname;
            const char* s2 = reinterpret_cast< const char* >( section->Name );

            unsigned char c1, c2;
            do {
                c1 = (unsigned char)*s1++;
                c2 = (unsigned char)*s2++;
                if ( c1 == '\0' ) {
                    break;
                }
            } while ( c1 == c2 );
            
            if ( c1 - c2 == 0 ) {
                return section;
            }

        }
        return nullptr;
    }

    void* section_data( unsigned int index )
    {
        return reinterpret_cast< char* >( base ) + section_hdr( index )->PointerToRawData;
    }

    void* section_data( const char* sname )
    {
        auto section = section_hdr( sname );
        if ( section ) {
            return rva2va( section->VirtualAddress );
        }
        return nullptr;
    }
};
