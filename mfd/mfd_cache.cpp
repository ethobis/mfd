#include "mfd_cache.h"

NTSTATUS MFDGetFileId(
	_In_ PFLT_INSTANCE pInstance,
	_In_ PFILE_OBJECT pFileObject,
	_Out_ PFILTER_FILE_REFERENCE pFileId
)
{
	NTSTATUS status = STATUS_SUCCESS;
	FLT_FILESYSTEM_TYPE FileSystemType;
	FILE_ID_INFORMATION FileIdInfo = { 0, };
	FILE_INTERNAL_INFORMATION FileInternalInfo = { 0, };

	status = FltGetFileSystemType(pInstance, &FileSystemType);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	if (FileSystemType == FLT_FSTYPE_REFS)
	{
		status = FltQueryInformationFile(
			pInstance,
			pFileObject,
			&FileIdInfo,
			sizeof(FILE_ID_INFORMATION),
			FileIdInformation,
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			goto _RET;
		}

		RtlCopyMemory(&(pFileId->FileId128), &(FileIdInfo.FileId), sizeof(pFileId->FileId128));
	}
	else
	{
		status = FltQueryInformationFile(
			pInstance,
			pFileObject,
			&FileInternalInfo,
			sizeof(FILE_INTERNAL_INFORMATION),
			FileInternalInformation,
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			goto _RET;
		}

		pFileId->FileId64.Value = FileInternalInfo.IndexNumber.QuadPart;
		pFileId->FileId64.UpperZeroes = 0;
	}

_RET:
	return status;
}

RTL_GENERIC_COMPARE_RESULTS NTAPI MFDCompareTableEntry(
	_In_ PRTL_GENERIC_TABLE pGenericTable,
	_In_ PVOID pvLhs,
	_In_ PVOID pvRhs
)
{
	PFILTER_GENERIC_TABLE pLhs = (PFILTER_GENERIC_TABLE)pvLhs;
	PFILTER_GENERIC_TABLE pRhs = (PFILTER_GENERIC_TABLE)pvRhs;

	UNREFERENCED_PARAMETER(pGenericTable);

	if (pLhs->FileId.FileId64.Value < pRhs->FileId.FileId64.Value)
	{
		return GenericLessThan;
	}
	else if (pLhs->FileId.FileId64.Value > pRhs->FileId.FileId64.Value)
	{
		return GenericGreaterThan;
	}
	else if (pLhs->FileId.FileId64.UpperZeroes < pRhs->FileId.FileId64.UpperZeroes)
	{
		return GenericLessThan;
	}
	else if (pLhs->FileId.FileId64.UpperZeroes > pRhs->FileId.FileId64.UpperZeroes)
	{
		return GenericGreaterThan;
	}

	return GenericEqual;
}

PVOID NTAPI MFDAllocateTableEntry(
	_In_ PRTL_GENERIC_TABLE pGenericTable,
	_In_ CLONG ByteSize
)
{
	UNREFERENCED_PARAMETER(pGenericTable);
	return ExAllocatePoolWithTag(PagedPool, ByteSize, MFD_CACHE_TAG);
}

VOID NTAPI MFDFreeTableEntry(
	_In_ PRTL_GENERIC_TABLE pGenericTable,
	_In_ PVOID pvEntry
)
{
	UNREFERENCED_PARAMETER(pGenericTable);
	ExFreePoolWithTag(pvEntry, MFD_CACHE_TAG);
}