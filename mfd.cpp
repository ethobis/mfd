#include "mfd.h"
#include "mfd_thread_notify.h"
#include "mfd_process_notify.h"
#include "mfd_image_notify.h"

MFD_CONTEXT MFDContext = { 0, };

NTSTATUS
FLTAPI MFDPortMessage(
	_In_ PVOID pvConnectionCookie,
	_In_ PVOID pvInputBuffer,
	_In_ ULONG ulInputBufferSize,
	_Out_ PVOID pvOutputBuffer,
	_Out_ ULONG ulOutputBufferSize,
	_Out_ PULONG pulRetOutputBufferSize
)
{
	NTSTATUS	status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pvConnectionCookie);
	UNREFERENCED_PARAMETER(pvInputBuffer);
	UNREFERENCED_PARAMETER(ulInputBufferSize);
	UNREFERENCED_PARAMETER(pvOutputBuffer);
	UNREFERENCED_PARAMETER(ulOutputBufferSize);
	UNREFERENCED_PARAMETER(pulRetOutputBufferSize);

	PAGED_CODE();

	return status;
}

NTSTATUS
FLTAPI MFDPortConnect(
	_In_ PFLT_PORT pClientPort,
	_In_ PVOID pvServerPortCookie,
	_In_ PVOID pvConnectionContext,
	_In_ ULONG ulSizeOfContext,
	_In_ PVOID *pvConnectionCookie
)
{
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pClientPort);
	UNREFERENCED_PARAMETER(pvServerPortCookie);
	UNREFERENCED_PARAMETER(pvConnectionContext);
	UNREFERENCED_PARAMETER(ulSizeOfContext);
	UNREFERENCED_PARAMETER(pvConnectionCookie);

	PAGED_CODE();

	return status;
}

VOID
FLTAPI MFDPortDisconnect(
	_In_ PVOID pvConnectionCookie
)
{
	UNREFERENCED_PARAMETER(pvConnectionCookie);

	PAGED_CODE();

	return;
}

NTSTATUS
FLTAPI MFDInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	return status;
}

VOID
FLTAPI MFDInstanceTeardown(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
)
{
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(Reason);

	PAGED_CODE();

	return;
}

NTSTATUS
FLTAPI DriverUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(Flags);

	if (NULL != MFDContext.pClientPort)
	{
		FltCloseClientPort(MFDContext.pMFDFilter, &MFDContext.pClientPort);
	}

	if (NULL != MFDContext.pServerPort)
	{
		FltCloseCommunicationPort(MFDContext.pServerPort);
	}

	if (NULL != MFDContext.pMFDFilter)
	{
		FltUnregisterFilter(MFDContext.pMFDFilter);
	}

	MFDRemoveImageNotifyRoutine(MFDLoadImageNotifyRoutine);

	MFDRemoveProcessNotifyRoutine(MFDProcessNotifyRoutine);
	MFDDeleteAllProcess();

	MFDRemoveThreadNotifyRoutine(MFDThreadNotifyRoutine);
	MFDDeleteAllThread();

	return status;
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT pDriverObject,
	_In_ PUNICODE_STRING puniRegistryPath
)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING uniPortName = { 0, };
	OBJECT_ATTRIBUTES oa = { 0, };
	PSECURITY_DESCRIPTOR pSD = NULL;

	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(puniRegistryPath);

	PAGED_CODE();

	status = FltRegisterFilter(pDriverObject, &FilterRegistration, &MFDContext.pMFDFilter);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	RtlInitUnicodeString(&uniPortName, FLT_FILTER_NAME);
	InitializeObjectAttributes(
		&oa,
		&uniPortName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		pSD
	);
	
	status = FltCreateCommunicationPort(
		MFDContext.pMFDFilter,
		&MFDContext.pServerPort,
		&oa,
		NULL,
		(PFLT_CONNECT_NOTIFY)MFDPortConnect,
		(PFLT_DISCONNECT_NOTIFY)MFDPortDisconnect,
		(PFLT_MESSAGE_NOTIFY)MFDPortMessage,
		1
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = FltStartFiltering(MFDContext.pMFDFilter);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	MFDSetThreadNotifyRoutine(MFDThreadNotifyRoutine);
	MFDSetProcessNotifyRoutine(MFDProcessNotifyRoutine);
	MFDSetImageNotifyRoutine(MFDLoadImageNotifyRoutine);

	return status;

_RET:
	if (NULL != MFDContext.pServerPort)
	{
		FltCloseCommunicationPort(MFDContext.pServerPort);
	}

	if (NULL != pSD)
	{
		FltFreeSecurityDescriptor(pSD);
	}

	if (NULL != MFDContext.pMFDFilter)
	{
		FltUnregisterFilter(MFDContext.pMFDFilter);
	}

	return status;
}