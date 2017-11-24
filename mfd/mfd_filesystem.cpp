#include "mfd_filesystem.h"

VOID
GetEnumerateVolume(
	_In_ PFLT_FILTER pFltFilter
)
{
	NTSTATUS status = STATUS_SUCCESS;
	FILTER_VOLUME_STANDARD_INFORMATION* pFilterVolumeStdInfo = NULL;
	ULONG ulReturnBytes = 0;
	ULONG ulIndex = 0;
	ULONG ulNumberOfVolume = 0;

	if (NULL == pFltFilter)
	{
		goto _RET;
	}

	status = FltEnumerateVolumes(pFltFilter, NULL, 0, &ulNumberOfVolume);

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
			NULL,
			NULL,
			&ulReturnBytes
			);

		if (STATUS_BUFFER_TOO_SMALL == status)
		{
			if (NULL == ulReturnBytes)
			{
				goto _RET;
			}

			pFilterVolumeStdInfo = (PFILTER_VOLUME_STANDARD_INFORMATION)ExAllocatePool(NonPagedPool, ulReturnBytes);

			if (NULL == pFilterVolumeStdInfo)
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

			if (NULL != pFilterVolumeStdInfo)
			{
				ExFreePool(pFilterVolumeStdInfo);
				pFilterVolumeStdInfo = NULL;
			}
		}
	}

_RET:
	if (NULL != pFilterVolumeStdInfo)
	{
		ExFreePool(pFilterVolumeStdInfo);
		pFilterVolumeStdInfo = NULL;
	}

	return;
}
