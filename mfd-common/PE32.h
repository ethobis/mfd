#ifndef __PE32__
#define __PE32__

#pragma warning(push)
#pragma warning(disable:4510)
#pragma warning(disable:4512)
#pragma warning(disable:4610)
#include <fltKernel.h>
#pragma warning(pop)
#pragma optimize("", off)

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

/* PE DOS 헤더 (40 byte) */
typedef struct _IMAGE_DOS_HEADER
{
	WORD		e_magic;	// MZ
	WORD		e_cblp;
	WORD		e_cp;
	WORD		e_crlc;
	WORD		e_cparhdr;
	WORD		e_minalloc;
	WORD		e_maxalloc;
	WORD		e_ss;
	WORD		e_sp;
	WORD		e_csum;
	WORD		e_ip;
	WORD		e_cs;
	WORD		e_lfarlc;
	WORD		e_ovno;
	WORD		e_res[4];
	WORD		e_oemid;
	WORD		e_oeminfo;
	WORD		e_res2[10];
	DWORD		e_lfanew;	// Next Pointer
}IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

/* PE Image File 헤더(20 byte) */
typedef struct _IMAGE_FILE_HEADER
{
	WORD		Machine;
	WORD		NumberOfSections;
	DWORD		TimeDataStamp;
	DWORD		PointerToSymbolTable;
	DWORD		NumberOfSymbols;
	WORD		SizeOfOptionalHeader;
	WORD		Characteristics;
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_NUMBEROF_DIRECTORTY_ENTRIES		16

#define IMAGE_DIRECTORY_ENTRY_EXPORT			0
#define IMAGE_DIRECTORY_ENTRY_IMPORT			1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE			2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION			3
#define IMAGE_DIRECTORY_ENTRY_SECURITY			4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC			5
#define IMAGE_DIRECTORY_ENTRY_DEBUG				6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE		7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR			8
#define IMAGE_DIRECTORY_ENTRY_TLS				9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG		10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT		11
#define IMAGE_DIRECTORY_ENTRY_ENTRY_IAT			12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT		13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	14

/* PE Data Directory 헤더 */
typedef struct _IMAGE_DATA_DIRECTORY
{
	DWORD		VirtualAddress;
	DWORD		Size;
}IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

/* PE Image Optional 헤더 (96 byte) + Data Directory (128 Byte) */
typedef struct _IMAGE_OPTIONAL_HEADER32
{
	// Standard Fields
	WORD					Magic;
	BYTE					MajorLinkerVersion;
	BYTE					MinorLinkerVersion;
	DWORD					SizeOfCode;
	DWORD					SizeOfInitializedData;
	DWORD					SizeOfUninitializedData;
	DWORD					AddressOfEntryPoint;
	DWORD					BaseOfCode;
	DWORD					BaseOfData;
	// NT Additional Fields
	DWORD					ImageBase;
	DWORD					SectionAlignment;
	DWORD					FileAlignment;
	WORD					MajorOperatingSystemVersion;
	WORD					MinorOperatingSystemVersion;
	WORD					MajorImageVersion;
	WORD					MinorImageVersion;
	WORD					MajorSubsystemVersion;
	WORD					MinorSubsystemVersion;
	DWORD					Win32VersionValue;
	DWORD					SizeOfImage;
	DWORD					SizeOfHeaders;
	DWORD					CheckSum;
	WORD					Subsystem;
	WORD					DllCharacteristics;
	DWORD					SizeOfStackReserve;
	DWORD					SizeOfStackCommit;
	DWORD					SizeOfHeapReserve;
	DWORD					SizeOfHeapCommit;
	DWORD					LoaderFlags;
	DWORD					NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY	DataDirectory[IMAGE_NUMBEROF_DIRECTORTY_ENTRIES];

}IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

/* PE32+ Optional 헤더 */
typedef struct _IMAGE_OPTIONAL_HEADER64
{
	WORD					Magic;
	BYTE					MajorLinkerVersion;
	BYTE					MinorLinkerVersion;
	DWORD					SizeOfCode;
	DWORD					SizeOfInitializedData;
	DWORD					SizeOfUninitializedData;
	DWORD					AddressOfEntryPoint;
	DWORD					BaseOfCode;
	ULONGLONG				ImageBase;
	DWORD					SectionAlignment;
	DWORD					FIleAliignment;
	WORD					MajorOperatingSystemVersion;
	WORD					MinorOperatingSystemVersion;
	WORD					MajorImageVersion;
	WORD					MinorImageVersion;
	WORD					MajorSubsystemVersion;
	WORD					MinorSubsystemVersion;
	DWORD					Win32VersionValue;
	DWORD					SizeOfImage;
	DWORD					SizeOfHeaders;
	DWORD					CheckSum;
	WORD					Subsystem;
	WORD					DllCharacteristics;
	ULONGLONG				SizeOfStackReserve;
	ULONGLONG				SizeOfStackCommit;
	ULONGLONG				SizeOfHeapReserve;
	ULONGLONG				SizeOfHeapCommit;
	DWORD					LoaderFlags;
	DWORD					NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY	DataDirectory[IMAGE_NUMBEROF_DIRECTORTY_ENTRIES];
}IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

/* PE Image NT 헤더 */
typedef struct _IMAGE_NT_HEADER32
{
	DWORD						Signature;
	IMAGE_FILE_HEADER			FileHeader;
	IMAGE_OPTIONAL_HEADER32		OptionalHeader;
}IMAGE_NT_HEADER32, *PIMAGE_NT_HEADER32;

typedef struct _IMAGE_NT_HEADER64
{
	DWORD						Signature;
	IMAGE_FILE_HEADER			FileHeader;
	IMAGE_OPTIONAL_HEADER64		OptionalHeader;
}IMAGE_NT_HEADER64, *PIMAGE_NT_HEADER64;

#define IMAGE_SIZEOF_SHORT_NAME		8
#define IMAGE_SCN_CNT_CODE			0x00000020
#define IMAGE_SCN_CNT_MEM_EXECUTE	0x20000000
#define IMAGE_SCN_CNT_MEM_READ		0x40000000
#define IMAGE_SCN_CNT_MEM_WRITE		0x80000000

/* PE Image Section 헤더 */
typedef struct _IMAGE_SECTION_HEADER
{
	BYTE		Name[IMAGE_SIZEOF_SHORT_NAME];
	union
	{
		DWORD	PhysicalAddress;
		DWORD	VirtualSize;
	}Misc;
	DWORD		VirtualAddress;
	DWORD		SizeOfRawData;
	DWORD		PointerToRawData;
	DWORD		PointerToRelocations;
	DWORD		PointerToLinenumbers;
	WORD		NumberOfRelocations;
	WORD		NumberOfLinenumbers;
	DWORD		Characteristics;	
}IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

/* PE Export Table 헤더 */
typedef struct _IMAGE_EXPORT_DIRECTORY
{
	DWORD		Characteristrics;
	DWORD		TimeDateStamp;
	WORD		MajorVersion;
	WORD		MinorVersion;
	DWORD		Name;
	DWORD		Base;
	DWORD		NumberOfFunctions;
	DWORD		NumberOfNames;
	DWORD		AddressOfFunctions;
	DWORD		AddressOfNames;
	DWORD		AddressOfNameOrdinals;
}IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

#ifdef __cplusplus
extern "C" {
#endif



#ifdef __cplusplus
}
#endif

#endif