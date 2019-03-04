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
// ���� ���̵� ���ϴ� �Լ�
//

NTSTATUS MFDGetFileId(
	_In_ PFLT_INSTANCE pInstance,
	_In_ PFILE_OBJECT pFileObject,
	_Out_ PFILTER_FILE_REFERENCE pFileId
);

//
// GENERIC TABLE �� ��ƾ
//

RTL_GENERIC_COMPARE_RESULTS NTAPI MFDCompareTableEntry(
	_In_ PRTL_GENERIC_TABLE pGenericTable,
	_In_ PVOID pvLhs,
	_In_ PVOID pvRhs
);

//
// GENERIC TABLE ���� ��ƾ
//

PVOID NTAPI MFDAllocateTableEntry(
	_In_ PRTL_GENERIC_TABLE pGenericTable,
	_In_ CLONG ByteSize
);

//
// GENERIC TABLE ���� ��ƾ
//

VOID NTAPI MFDFreeTableEntry(
	_In_ PRTL_GENERIC_TABLE pGenericTable,
	_In_ PVOID pvEntry
);