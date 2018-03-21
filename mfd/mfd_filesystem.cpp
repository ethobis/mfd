#include "mfd_filesystem.h"

ULONG
GetVolumeDeviceCharacteristics(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects
)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ulRetVolumeDeviceType = 0;
	PFLT_VOLUME_PROPERTIES pFltVolumeProperties = nullptr;
	ULONG ulPropertiesSize = 0;
	ULONG ulRetPropertiesSize = 0;

	if (nullptr == pFltObjects)
	{
		goto _RET;
	}

	status = FltGetVolumeProperties(pFltObjects->Volume, nullptr, 0, &ulPropertiesSize);

	if (STATUS_BUFFER_TOO_SMALL == status)
	{
		pFltVolumeProperties = (PFLT_VOLUME_PROPERTIES)ExAllocatePool(NonPagedPool, ulPropertiesSize);

		if (nullptr == pFltVolumeProperties)
		{
			goto _RET;
		}

		status = FltGetVolumeProperties(pFltObjects->Volume, pFltVolumeProperties, ulPropertiesSize, &ulRetPropertiesSize);

		if (!NT_SUCCESS(status))
		{
			goto _RET;
		}

		ulRetVolumeDeviceType = pFltVolumeProperties->DeviceCharacteristics;
	}

_RET:
	if (nullptr != pFltVolumeProperties)
	{
		ExFreePool(pFltVolumeProperties);
		pFltVolumeProperties = nullptr;
	}
	
	return ulRetVolumeDeviceType;
}

BOOLEAN
GetVolumeDeviceName(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PWCHAR pwchOutVolumeDeviceName
)
{
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN bRetValue = false;
	PDEVICE_OBJECT pDiskDeviceObject = nullptr;
	UNICODE_STRING uniRetVolumeDeviceName = { 0, };

	if (nullptr == pFltObjects)
	{
		goto _RET;
	}

	status = FltGetDiskDeviceObject(pFltObjects->Volume, &pDiskDeviceObject);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = RtlVolumeDeviceToDosName(pDiskDeviceObject, &uniRetVolumeDeviceName);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	if (uniRetVolumeDeviceName.Length > 4)
	{
		goto _RET;
	}

	RtlCopyMemory(pwchOutVolumeDeviceName, uniRetVolumeDeviceName.Buffer, uniRetVolumeDeviceName.Length * sizeof(WCHAR));

	bRetValue = true;

_RET:
	if (nullptr != uniRetVolumeDeviceName.Buffer)
	{
		ExFreePool(uniRetVolumeDeviceName.Buffer);
	}

	if (nullptr != pDiskDeviceObject)
	{
		ObDereferenceObject(pDiskDeviceObject);
	}

	return bRetValue;
}

BOOLEAN
GetFilePath(
	_In_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PWCHAR* pwchOutFilePath,
	_In_ BOOLEAN bWithVolumeDosName
)
{
	BOOLEAN bRetValue = false;
	NTSTATUS status = STATUS_SUCCESS;
	PFLT_FILE_NAME_INFORMATION pFileNameInfo = nullptr;
	ULONG ulBufferLength = 0;
	ULONG ulBufferIndex = 0;
	WCHAR wchDosName[3] = { 0, };

	if (nullptr == pData || nullptr == pFltObjects)
	{
		goto _RET;
	}

	status = FltGetFileNameInformation(
		pData,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&pFileNameInfo
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = FltParseFileNameInformation(pFileNameInfo);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	if (bWithVolumeDosName)
	{
		ulBufferLength = 2 * sizeof(WCHAR);

		if (nullptr != pFileNameInfo->ParentDir.Buffer)
		{
			ulBufferLength += pFileNameInfo->ParentDir.Length;
		}

		if (nullptr != pFileNameInfo->FinalComponent.Buffer)
		{
			ulBufferLength += pFileNameInfo->FinalComponent.Length;
		}

		ulBufferLength += sizeof(WCHAR);
	}
	else
	{
		if (nullptr != pFileNameInfo->Name.Buffer)
		{
			ulBufferLength = pFileNameInfo->Name.Length + sizeof(WCHAR);
		}
	}

	(*pwchOutFilePath) = (PWCHAR)ExAllocatePool(NonPagedPool, ulBufferLength);

	if (nullptr == (*pwchOutFilePath))
	{
		goto _RET;
	}

	if (bWithVolumeDosName)
	{
		if (!GetVolumeDeviceName(pFltObjects, wchDosName))
		{
			goto _RET;
		}

		RtlCopyMemory((*pwchOutFilePath), wchDosName, 2 * sizeof(WCHAR));
		ulBufferIndex += 2;

		if (nullptr != pFileNameInfo->ParentDir.Buffer)
		{
			RtlCopyMemory(&(*pwchOutFilePath)[ulBufferIndex], pFileNameInfo->ParentDir.Buffer, pFileNameInfo->ParentDir.Length);
			ulBufferIndex += (pFileNameInfo->ParentDir.Length / sizeof(WCHAR));
		}

		if (nullptr != pFileNameInfo->FinalComponent.Buffer)
		{
			RtlCopyMemory(&(*pwchOutFilePath)[ulBufferIndex], pFileNameInfo->FinalComponent.Buffer, pFileNameInfo->FinalComponent.Length);
		}
	}
	else
	{
		RtlCopyMemory((*pwchOutFilePath), pFileNameInfo->Name.Buffer, pFileNameInfo->Name.Length);
	}

	bRetValue = true;

_RET:
	if (nullptr != pFileNameInfo)
	{
		FltReleaseFileNameInformation(pFileNameInfo);
		pFileNameInfo = nullptr;
	}

	return bRetValue;
}

void
GetEnumerateVolume(
	_In_ PFLT_FILTER pFltFilter
)
{
	NTSTATUS status = STATUS_SUCCESS;
	FILTER_VOLUME_STANDARD_INFORMATION* pFilterVolumeStdInfo = nullptr;
	ULONG ulReturnBytes = 0;
	ULONG ulIndex = 0;
	ULONG ulNumberOfVolume = 0;

	if (nullptr == pFltFilter)
	{
		goto _RET;
	}

	status = FltEnumerateVolumes(pFltFilter, nullptr, 0, &ulNumberOfVolume);

	if (0 == ulNumberOfVolume)
	{
		goto _RET;
	}

	for (ulIndex = 0; ulIndex < ulNumberOfVolume; ++ulIndex)
	{
		status = FltEnumerateVolumeInformation(
			pFltFilter,
			ulIndex,
			FilterVolumeStandardInformation,
			nullptr,
			0,
			&ulReturnBytes
			);

		if (STATUS_BUFFER_TOO_SMALL == status)
		{
			if (0 == ulReturnBytes)
			{
				goto _RET;
			}

			pFilterVolumeStdInfo = (PFILTER_VOLUME_STANDARD_INFORMATION)ExAllocatePool(NonPagedPool, ulReturnBytes);

			if (nullptr == pFilterVolumeStdInfo)
			{
				goto _RET;
			}

			RtlZeroMemory(pFilterVolumeStdInfo, ulReturnBytes);

			status = FltEnumerateVolumeInformation(
				pFltFilter,
				ulIndex,
				FilterVolumeStandardInformation,
				pFilterVolumeStdInfo,
				ulReturnBytes,
				&ulReturnBytes
				);

			if (NT_SUCCESS(status) &&
				FLT_FSTYPE_NTFS == pFilterVolumeStdInfo->FileSystemType)
			{
				// NTFS 볼륨 타입인 경우에 작업
			}

			if (nullptr != pFilterVolumeStdInfo)
			{
				ExFreePool(pFilterVolumeStdInfo);
				pFilterVolumeStdInfo = nullptr;
			}
		}
	}

_RET:
	if (nullptr != pFilterVolumeStdInfo)
	{
		ExFreePool(pFilterVolumeStdInfo);
		pFilterVolumeStdInfo = nullptr;
	}

	return;
}