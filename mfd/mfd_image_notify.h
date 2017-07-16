#ifndef __MFD_IMAGE_NOTIFY_H__
#define __MFD_IMAGE_NOTIFY_H__

#include <ntifs.h>
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

	VOID
	MFDLoadImageNotifyRoutine(
		_In_ PUNICODE_STRING puniFullImageName,
		_In_ HANDLE hProcessId,
		_In_ PIMAGE_INFO pImageInfo
	);

	NTSTATUS
	MFDSetImageNotifyRoutine(
		_In_ PVOID pvImageNotifyRoutine
	);

	NTSTATUS
	MFDRemoveImageNotifyRoutine(
		_In_ PVOID pvImageNotifyRoutine
	);

#ifdef __cplusplus
}
#endif

#endif