#include "mfd_function.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MFDOpenVolumeProperties)
#pragma alloc_text(PAGE, MFDCloseVolumeProperties)
#pragma alloc_text(PAGE, MFDGetVolumeName)
#pragma alloc_text(PAGE, MFDGetFilePath)
#endif

PFLT_VOLUME_PROPERTIES MFDOpenVolumeProperties(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PFLT_VOLUME_PROPERTIES pVolumeProperties = NULL;
	ULONG ulPropertiesSize = 0;
	ULONG ulRetSize = 0;

	PAGED_CODE();

	status = FltGetVolumeProperties(pFltObjects->Volume, NULL, 0, &ulPropertiesSize);

	if (status == STATUS_BUFFER_TOO_SMALL)
	{
		pVolumeProperties = (PFLT_VOLUME_PROPERTIES)ExAllocatePool(PagedPool, ulPropertiesSize);

		if (pVolumeProperties == NULL)
		{
			return NULL;
		}

		status = FltGetVolumeProperties(pFltObjects->Volume, pVolumeProperties, ulPropertiesSize, &ulRetSize);

		if (!NT_SUCCESS(status))
		{
			MFDCloseVolumeProperties(pVolumeProperties);
			return NULL;
		}

		return pVolumeProperties;
	}

	return NULL;
}

VOID MFDCloseVolumeProperties(
	_In_ PFLT_VOLUME_PROPERTIES pVolumeProperties
)
{
	PAGED_CODE();

	if (pVolumeProperties != NULL)
	{
		ExFreePool(pVolumeProperties);
		pVolumeProperties = NULL;
	}
}

BOOLEAN MFDGetVolumeName(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PUNICODE_STRING puniVolumeName
)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ulVolumeNameLength = 0;

	PAGED_CODE();

	status = FltGetVolumeName(pFltObjects->Volume, NULL, &ulVolumeNameLength);

	if (status == STATUS_BUFFER_TOO_SMALL)
	{
		puniVolumeName->MaximumLength = (USHORT)ulVolumeNameLength;
		puniVolumeName->Buffer = (PWCH)ExAllocatePool(PagedPool, ulVolumeNameLength);

		if (puniVolumeName->Buffer == NULL)
		{
			return FALSE;
		}

		RtlZeroMemory(puniVolumeName->Buffer, ulVolumeNameLength);

		status = FltGetVolumeName(pFltObjects->Volume, puniVolumeName, &ulVolumeNameLength);

		if (!NT_SUCCESS(status))
		{
			ExFreePool(puniVolumeName->Buffer);
			puniVolumeName->Buffer = NULL;
			return FALSE;
		}

		return TRUE;
	}

	return FALSE;
}

BOOLEAN MFDGetFilePath(
	_In_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PUNICODE_STRING puniOutFilePath
)
{
	BOOLEAN bRet = FALSE;
	NTSTATUS status = STATUS_SUCCESS;
	PFLT_FILE_NAME_INFORMATION pFileNameInfo = NULL;
	UNICODE_STRING uniVolumeName = { 0, };
	ULONG ulFileNameLength = 0;
	PUNICODE_STRING puniFileNameInfo = NULL;

	PAGED_CODE();

	status = FltGetFileNameInformation(
		pData,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&pFileNameInfo
	);

	if (NT_SUCCESS(status) &&
		pFileNameInfo->Name.Length > 0)
	{
		ulFileNameLength = pFileNameInfo->Name.Length;
		puniFileNameInfo = &pFileNameInfo->Name;
	}
	else
	{
		status = FltGetFileNameInformation(
			pData,
			FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
			&pFileNameInfo
		);

		if (NT_SUCCESS(status) &&
			pFileNameInfo->Name.Length > 0)
		{
			ulFileNameLength = pFileNameInfo->Name.Length;
			puniFileNameInfo = &pFileNameInfo->Name;
		}
		else
		{
			if (MFDGetVolumeName(pFltObjects, &uniVolumeName))
			{
				status = RtlUnicodeStringCopy(puniOutFilePath, &uniVolumeName);

				if (NT_SUCCESS(status))
				{
					status = RtlUnicodeStringCat(puniOutFilePath, &pFltObjects->FileObject->FileName);

					if (NT_SUCCESS(status))
					{
						bRet = TRUE;
					}
				}

				ExFreePool(uniVolumeName.Buffer);
				uniVolumeName.Buffer = NULL;
			}

			return bRet;
		}
	}

	status = RtlUnicodeStringCopy(puniOutFilePath, puniFileNameInfo);

	if (NT_SUCCESS(status))
	{
		bRet = TRUE;
	}

	if (pFileNameInfo != NULL)
	{
		FltReleaseFileNameInformation(pFileNameInfo);
		pFileNameInfo = NULL;
	}

	return bRet;
}