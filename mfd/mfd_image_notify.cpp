#include "mfd_image_notify.h"

VOID
MFDLoadImageNotifyRoutine(
	_In_ PUNICODE_STRING puniFullImageName,
	_In_ HANDLE hProcessId,
	_In_ PIMAGE_INFO pImageInfo
)
{
	UNREFERENCED_PARAMETER(puniFullImageName);
	UNREFERENCED_PARAMETER(hProcessId);
	UNREFERENCED_PARAMETER(pImageInfo);

	return;
}

NTSTATUS
MFDSetImageNotifyRoutine(
	_In_ PVOID pvImageNotifyRoutine
)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (NULL == pvImageNotifyRoutine)
	{
		goto _RET;
	}

	status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)pvImageNotifyRoutine);

_RET:
	return status;
}

NTSTATUS
MFDRemoveImageNotifyRoutine(
	_In_ PVOID pvImageNotifyRoutine
)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (NULL == pvImageNotifyRoutine)
	{
		goto _RET;
	}

	status = PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)pvImageNotifyRoutine);

_RET:
	return status;
}