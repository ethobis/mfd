#pragma once
#define RTL_USE_AVL_TABLES 0
#include <fltKernel.h>

#define MFD_CACHE_TAG 'tdfm'

typedef struct _FILTER_FILE_REFERENCE
{
	struct
	{
		ULONGLONG Value;
		ULONGLONG UpperZeroes;
	}FileId64;
	FILE_ID_128 FileId128;
}FILTER_FILE_REFERENCE, *PFILTER_FILE_REFERENCE;

typedef struct _FILTER_GENERIC_TABLE
{
	FILTER_FILE_REFERENCE FileId;
	ULONG FileState;
}FILTER_GENERIC_TABLE, *PFILTER_GENERIC_TABLE;
#define FILTER_GENERIC_TABLE_SIZE sizeof(FILTER_GENERIC_TABLE)

//
// 파일 아이디 구하는 함수
//

NTSTATUS MFDGetFileId(
	_In_ PFLT_INSTANCE pInstance,
	_In_ PFILE_OBJECT pFileObject,
	_Out_ PFILTER_FILE_REFERENCE pFileId
);

//
// GENERIC TABLE 비교 루틴
//

RTL_GENERIC_COMPARE_RESULTS NTAPI MFDCompareTableEntry(
	_In_ PRTL_GENERIC_TABLE pGenericTable,
	_In_ PVOID pvLhs,
	_In_ PVOID pvRhs
);

//
// GENERIC TABLE 생성 루틴
//

PVOID NTAPI MFDAllocateTableEntry(
	_In_ PRTL_GENERIC_TABLE pGenericTable,
	_In_ CLONG ByteSize
);

//
// GENERIC TABLE 해제 루틴
//

VOID NTAPI MFDFreeTableEntry(
	_In_ PRTL_GENERIC_TABLE pGenericTable,
	_In_ PVOID pvEntry
);