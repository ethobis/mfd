#pragma once
#pragma warning(push)
#pragma warning(disable:4510)
#pragma warning(disable:4512)
#pragma warning(disable:4610)
#include <fltKernel.h>
#pragma warning(pop)
#pragma optimize("", off)

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_OS2_SIGNATURE 0x454E
#define IMAGE_OS2_SIGNATURE_LE 0x454C
#define IMAGE_VXD_SIGNATURE 0x454C
#define IMAGE_NT_SIGNATURE 0x00004550

typedef struct _IMAGE_DOS_HEADER {			// DOS .EXE header
	USHORT   e_magic;						// Magic number
	USHORT   e_cblp;						// Bytes on last page of file
	USHORT   e_cp;							// Pages in file
	USHORT   e_crlc;						// Relocations
	USHORT   e_cparhdr;						// Size of header in paragraphs
	USHORT   e_minalloc;					// Minimum extra paragraphs needed
	USHORT   e_maxalloc;					// Maximum extra paragraphs needed
	USHORT   e_ss;							// Initial (relative) SS value
	USHORT   e_sp;							// Initial SP value
	USHORT   e_csum;						// Checksum
	USHORT   e_ip;							// Initial IP value
	USHORT   e_cs;							// Initial (relative) CS value
	USHORT   e_lfarlc;						// File address of relocation table
	USHORT   e_ovno;						// Overlay number
	USHORT   e_res[4];						// Reserved words
	USHORT   e_oemid;						// OEM identifier (for e_oeminfo)
	USHORT   e_oeminfo;						// OEM information; e_oemid specific
	USHORT   e_res2[10];					// Reserved words
	LONG   e_lfanew;						// File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	USHORT    Machine;
	USHORT    NumberOfSections;
	ULONG   TimeDateStamp;
	ULONG   PointerToSymbolTable;
	ULONG   NumberOfSymbols;
	USHORT    SizeOfOptionalHeader;
	USHORT    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20

#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved externel references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Agressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                    0x1000  // System File.
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4 little-endian
#define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
#define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian
#define IMAGE_FILE_MACHINE_THUMB             0x01c2
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI Byte Code
#define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041  // M32R little-endian
#define IMAGE_FILE_MACHINE_CEE               0xC0EE

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG   VirtualAddress;
	ULONG   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

//
// Optional header format.
//

typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	USHORT    Magic;
	UCHAR    MajorLinkerVersion;
	UCHAR    MinorLinkerVersion;
	ULONG   SizeOfCode;
	ULONG   SizeOfInitializedData;
	ULONG   SizeOfUninitializedData;
	ULONG   AddressOfEntryPoint;
	ULONG   BaseOfCode;
	ULONG   BaseOfData;

	//
	// NT additional fields.
	//

	ULONG   ImageBase;
	ULONG   SectionAlignment;
	ULONG   FileAlignment;
	USHORT    MajorOperatingSystemVersion;
	USHORT    MinorOperatingSystemVersion;
	USHORT    MajorImageVersion;
	USHORT    MinorImageVersion;
	USHORT    MajorSubsystemVersion;
	USHORT    MinorSubsystemVersion;
	ULONG   Win32VersionValue;
	ULONG   SizeOfImage;
	ULONG   SizeOfHeaders;
	ULONG   CheckSum;
	USHORT    Subsystem;
	USHORT    DllCharacteristics;
	ULONG   SizeOfStackReserve;
	ULONG   SizeOfStackCommit;
	ULONG   SizeOfHeapReserve;
	ULONG   SizeOfHeapCommit;
	ULONG   LoaderFlags;
	ULONG   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	USHORT        Magic;
	UCHAR        MajorLinkerVersion;
	UCHAR        MinorLinkerVersion;
	ULONG       SizeOfCode;
	ULONG       SizeOfInitializedData;
	ULONG       SizeOfUninitializedData;
	ULONG       AddressOfEntryPoint;
	ULONG       BaseOfCode;
	ULONGLONG   ImageBase;
	ULONG       SectionAlignment;
	ULONG       FileAlignment;
	USHORT        MajorOperatingSystemVersion;
	USHORT        MinorOperatingSystemVersion;
	USHORT        MajorImageVersion;
	USHORT        MinorImageVersion;
	USHORT        MajorSubsystemVersion;
	USHORT        MinorSubsystemVersion;
	ULONG       Win32VersionValue;
	ULONG       SizeOfImage;
	ULONG       SizeOfHeaders;
	ULONG       CheckSum;
	USHORT        Subsystem;
	USHORT        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	ULONG       LoaderFlags;
	ULONG       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;


#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

#ifdef _WIN64
typedef IMAGE_OPTIONAL_HEADER64             IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64            PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC         IMAGE_NT_OPTIONAL_HDR64_MAGIC
typedef PIMAGE_NT_HEADERS64					PIMAGE_NT_HEADERS;
typedef IMAGE_NT_HEADERS64					IMAGE_NT_HEADERS;
#else
typedef IMAGE_OPTIONAL_HEADER32             IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32            PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC         IMAGE_NT_OPTIONAL_HDR32_MAGIC
typedef PIMAGE_NT_HEADERS32					PIMAGE_NT_HEADERS;
typedef IMAGE_NT_HEADERS32					IMAGE_NT_HEADERS;
#endif




// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
	((ULONG_PTR)(ntheader) +                                            \
	FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
	((ntheader))->FileHeader.SizeOfOptionalHeader   \
	))

// Subsystem Values

#define IMAGE_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI            7   // image runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS       8   // image is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9   // Image runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION      10  //
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11   //
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12  //
#define IMAGE_SUBSYSTEM_EFI_ROM              13
#define IMAGE_SUBSYSTEM_XBOX                 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

// DllCharacteristics Entries

//      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040     // DLL can move.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080     // Code Integrity Image
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT    0x0100     // Image is NX compatible
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200     // Image understands isolation and doesn't want it
#define IMAGE_DLLCHARACTERISTICS_NO_SEH       0x0400     // Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLCHARACTERISTICS_NO_BIND      0x0800     // Do not bind this image.
//                                            0x1000     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER   0x2000     // Driver uses WDM model
//                                            0x4000     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE     0x8000

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
	UCHAR    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		ULONG   PhysicalAddress;
		ULONG   VirtualSize;
	} Misc;
	ULONG   VirtualAddress;
	ULONG   SizeOfRawData;
	ULONG   PointerToRawData;
	ULONG   PointerToRelocations;
	ULONG   PointerToLinenumbers;
	USHORT    NumberOfRelocations;
	USHORT    NumberOfLinenumbers;
	ULONG   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

//
// Section characteristics.
//
//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
//                                           0x00002000  // Reserved.
//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                0x00008000
//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000

#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  //
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  //
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  //
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  //
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  //
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  //
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000  //
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000  //
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  //
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  //
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  //
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  //
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  //
// Unused                                    0x00F00000
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.

//
// Based relocation format.
//

typedef struct _IMAGE_BASE_RELOCATION {
	ULONG   VirtualAddress;
	ULONG   SizeOfBlock;
	//  USHORT    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;

//
// Based relocation types.
//

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MIPS_JMPADDR          5
#define IMAGE_REL_BASED_MIPS_JMPADDR16        9
#define IMAGE_REL_BASED_IA64_IMM64            9
#define IMAGE_REL_BASED_DIR64                 10

typedef struct _IMAGE_IMPORT_BY_NAME {
	USHORT    Hint;
	UCHAR    Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		ULONG   Characteristics;            // 0 for terminating null import descriptor
		ULONG   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} DUMMYUNIONNAME;
	ULONG   TimeDateStamp;                  // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)

	ULONG   ForwarderChain;                 // -1 if no forwarders
	ULONG   Name;
	ULONG   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	ULONG   Characteristics;
	ULONG   TimeDateStamp;
	USHORT    MajorVersion;
	USHORT    MinorVersion;
	ULONG   Name;
	ULONG   Base;
	ULONG   NumberOfFunctions;
	ULONG   NumberOfNames;
	ULONG   AddressOfFunctions;     // RVA from base of image
	ULONG   AddressOfNames;         // RVA from base of image
	ULONG   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY {
	ULONG   Characteristics;
	ULONG   TimeDateStamp;
	USHORT  MajorVersion;
	USHORT  MinorVersion;
	USHORT  NumberOfNamedEntries;
	USHORT  NumberOfIdEntries;
	//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
#pragma warning(push)
#pragma warning(disable : 4201)
	union  {
		struct{
			ULONG NameOffset : 31;
			ULONG NameIsString : 1;
		};
		ULONG   Name;
		USHORT  Id;
	};
	union {
		ULONG   OffsetToData;
		struct {
			ULONG   OffsetToDirectory : 31;
			ULONG   DataIsDirectory : 1;
		};
	};
#pragma warning(pop)
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

#define DEF_RES_ID_INT			0
#define DEF_RES_ID_STRING		1
#define DEF_RES_TYPE_VERSION	0x10

#define DEF_DOS_HEADER_SIG		0x5A4D
#define DEF_NT_HEADER_SIG		0x4550

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
	ULONG   OffsetToData;
	ULONG   Size;
	ULONG   CodePage;
	ULONG   Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

typedef struct tagVS_FIXEDFILEINFO
{
	ULONG   dwSignature;            /* e.g. 0xfeef04bd */
	ULONG   dwStrucVersion;         /* e.g. 0x00000042 = "0.42" */
	ULONG   dwFileVersionMS;        /* e.g. 0x00030075 = "3.75" */
	ULONG   dwFileVersionLS;        /* e.g. 0x00000031 = "0.31" */
	ULONG   dwProductVersionMS;     /* e.g. 0x00030010 = "3.10" */
	ULONG   dwProductVersionLS;     /* e.g. 0x00000031 = "0.31" */
	ULONG   dwFileFlagsMask;        /* = 0x3F for version "0.42" */
	ULONG   dwFileFlags;            /* e.g. VFF_DEBUG | VFF_PRERELEASE */
	ULONG   dwFileOS;               /* e.g. VOS_DOS_WINDOWS16 */
	ULONG   dwFileType;             /* e.g. VFT_DRIVER */
	ULONG   dwFileSubtype;          /* e.g. VFT2_DRV_KEYBOARD */
	ULONG   dwFileDateMS;           /* e.g. 0 */
	ULONG   dwFileDateLS;           /* e.g. 0 */
} VS_FIXEDFILEINFO;

#pragma pack(push, 1)
typedef struct _VARFILEINFO
{
	USHORT usLength;
	USHORT usValueLength;
	USHORT usType;
	WCHAR szKey;
} VARFILEINFO, *PVARFILEINFO;

typedef struct _STRINGTABLE
{
	USHORT usLength;
	USHORT usValueLength;
	USHORT usType;
	WCHAR szKey[9];	// 040904B0
} STRINGTABLE, *PSTRINGTABLE;

typedef struct
{
	USHORT usLength;
	USHORT usValueLength;
	USHORT usType;
	WCHAR szKey[15]; // StringFileInfo
} STRINGFILEINFO, *PSTRINGFILEINFO;

typedef struct
{
	USHORT usLength;
	USHORT usValueLength;
	USHORT usType;
	WCHAR szKey[17];	//VS_VERSION_INFO
	VS_FIXEDFILEINFO Value;
} VS_VERSIONINFO, *PVS_VERSIONINFO;
#pragma pack(pop)

#ifdef _BFUNICODE_
#define MAKEINTRESOURCE(i) ((LPWSTR)((ULONG_PTR)((USHORT)(i))))
#else //!_BFUNICODE_
#define MAKEINTRESOURCE(i) ((LPSTR)((ULONG_PTR)((USHORT)(i))))
#endif //_BF_UNICODE_

//
// Resource Types
//

#define RT_ACCELERATOR		MAKEINTRESOURCE(9)		//Accelerator table.
#define RT_ANICURSOR		MAKEINTRESOURCE(21)		//Animated cursor.
#define RT_ANIICON			MAKEINTRESOURCE(22)		//Animated icon.
#define RT_BITMAP			MAKEINTRESOURCE(2)		//Bitmap resource.
#define RT_CURSOR			MAKEINTRESOURCE(1)		//Hardware - dependent cursor resource.
#define	RT_DIALOG			MAKEINTRESOURCE(5)		//Dialog box.
#define RT_DLGINCLUDE		MAKEINTRESOURCE(17)		//Allows a resource editing tool to associate a string with an.rc file.Typically, the string is the name of the header file that provides symbolic names.The resource compiler parses the string but otherwise ignores the value.For example, 1 DLGINCLUDE "MyFile.h"
#define RT_FONT				MAKEINTRESOURCE(8)		//Font resource.
#define RT_FONTDIR			MAKEINTRESOURCE(7)		//Font directory resource.
#define RT_GROUP_CURSOR		MAKEINTRESOURCE((ULONG_PTR)(RT_CURSOR)+11) //Hardware - independent cursor resource.
#define RT_GROUP_ICON		MAKEINTRESOURCE((ULONG_PTR)(RT_ICON)+11) //Hardware - independent icon resource.
#define RT_HTML				MAKEINTRESOURCE(23)		//HTML resource.
#define RT_ICON				MAKEINTRESOURCE(3)		//Hardware - dependent icon resource.
#define RT_MANIFEST			MAKEINTRESOURCE(24)		//Side - by - Side Assembly Manifest.
#define RT_MENU				MAKEINTRESOURCE(4)		//Menu resource.
#define RT_MESSAGETABLE		MAKEINTRESOURCE(11)		//Message - table entry.
#define RT_PLUGPLAY			MAKEINTRESOURCE(19)		//Plug and Play resource.
#define RT_RCDATA			MAKEINTRESOURCE(10)		//Application - defined resource(raw data).
#define RT_STRING			MAKEINTRESOURCE(6)		//String - table entry.
#define RT_VERSION			MAKEINTRESOURCE(16)		//Version resource.
#define RT_VXD				MAKEINTRESOURCE(20)		//VXD.

typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
	USHORT Length;
	WCHAR NameString[1];
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;

#ifndef IS_INTRESOURCE
#define IS_INTRESOURCE(_r) ((((ULONG_PTR)(_r)) >> 16) == 0)
#endif

#ifndef MAKEINTRESOURCEW
#define MAKEINTRESOURCEW(i) ((LPWSTR)((ULONG_PTR)((SHORT)(i))))
#endif

#define VS_VERSION_INFO 1