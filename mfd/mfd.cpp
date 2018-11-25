#include "mfd.h"
#include "mfd_handler.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MFDConnect)
#pragma alloc_text(PAGE, MFDReceive)
#pragma alloc_text(PAGE, MFDDisconnect)
#pragma alloc_text(PAGE, MFDInstanceSetup)
#pragma alloc_text(PAGE, MFDInstanceTeardown)
#pragma alloc_text(PAGE, DriverUnload)
#endif

FILTER_CONTEXT g_CtxFilter = { NULL, };

NTSTATUS FLTAPI MFDConnect(
	_In_ PFLT_PORT pClientPort,
	_In_ PVOID pvServerPortCookie,
	_In_ PVOID pvConnectionContext,
	_In_ ULONG ulSizeOfContext,
	_In_ PVOID *pvConnectionCookie
)
{
	NTSTATUS status = STATUS_SUCCESS;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(pvServerPortCookie);
	UNREFERENCED_PARAMETER(pvConnectionContext);
	UNREFERENCED_PARAMETER(ulSizeOfContext);
	UNREFERENCED_PARAMETER(pvConnectionCookie);

	g_CtxFilter.pClientPort = pClientPort;

	return status;
}

NTSTATUS FLTAPI MFDReceive(
	_In_ PVOID pvConnectionCookie,
	_In_ PVOID pvInputBuffer,
	_In_ ULONG ulInputBufferSize,
	_Out_ PVOID pvOutputBuffer,
	_Out_ ULONG ulOutputBufferSize,
	_Out_ PULONG pulRetOutputBufferSize
)
{
	NTSTATUS status = STATUS_SUCCESS;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(pvConnectionCookie);
	UNREFERENCED_PARAMETER(pvInputBuffer);
	UNREFERENCED_PARAMETER(ulInputBufferSize);
	UNREFERENCED_PARAMETER(pvOutputBuffer);
	UNREFERENCED_PARAMETER(ulOutputBufferSize);
	UNREFERENCED_PARAMETER(pulRetOutputBufferSize);

	return status;
}

VOID FLTAPI MFDDisconnect(
	_In_ PVOID pvConnectionCookie
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(pvConnectionCookie);

	if (NULL != g_CtxFilter.pClientPort)
	{
		FltCloseClientPort(g_CtxFilter.pFilter, &g_CtxFilter.pClientPort);
		g_CtxFilter.pClientPort = NULL;
	}

	return;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDPreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS FilterRet = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(pCompletionContext);

	switch (pData->Iopb->MajorFunction)
	{
	case IRP_MJ_CREATE:
		FilterRet = MFDCreatePreRoutine(
			pData,
			pFltObjects,
			pCompletionContext
		);
		break;
	case IRP_MJ_CLEANUP:
		FilterRet = MFDCleanupPreRoutine(
			pData,
			pFltObjects,
			pCompletionContext
		);		
		break;
	}

	return FilterRet;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI MFDPostRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS FilterRet = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(pCompletionContext);

	switch (pData->Iopb->MajorFunction)
	{
	case IRP_MJ_CREATE:
		FilterRet = MFDCreatePostRoutine(
			pData,
			pFltObjects,
			pCompletionContext,
			Flags
		);
		break;
	}

	return FilterRet;
}

NTSTATUS FLTAPI MFDInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
	NTSTATUS status = STATUS_SUCCESS;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	return status;
}

VOID FLTAPI MFDInstanceTeardown(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(Reason);
	return;
}

NTSTATUS FLTAPI DriverUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	NTSTATUS status = STATUS_SUCCESS;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(Flags);

	if (NULL != g_CtxFilter.pServerPort)
	{
		FltCloseCommunicationPort(g_CtxFilter.pServerPort);
		g_CtxFilter.pServerPort = NULL;
	}

	if (NULL != g_CtxFilter.pFilter)
	{
		FltUnregisterFilter(g_CtxFilter.pFilter);
		g_CtxFilter.pFilter = NULL;
	}

	return status;
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT pDriverObject,
	_In_ PUNICODE_STRING puniRegistryPath
)
{
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oa = { 0, };
	PSECURITY_DESCRIPTOR seucirtyDescriptor = NULL;
	UNICODE_STRING uniPortName = { 0, };

	UNREFERENCED_PARAMETER(puniRegistryPath);

	status = FltRegisterFilter(
		pDriverObject,
		&FilterRegistration,
		&g_CtxFilter.pFilter
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = FltBuildDefaultSecurityDescriptor(
		&seucirtyDescriptor,
		FLT_PORT_ALL_ACCESS
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	RtlInitUnicodeString(&uniPortName, MFD_FILTER_NAME);
	InitializeObjectAttributes(
		&oa,
		&uniPortName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		seucirtyDescriptor
	);

	status = FltCreateCommunicationPort(
		g_CtxFilter.pFilter,
		&g_CtxFilter.pServerPort,
		&oa,
		NULL,
		(PFLT_CONNECT_NOTIFY)MFDConnect,
		(PFLT_DISCONNECT_NOTIFY)MFDDisconnect,
		(PFLT_MESSAGE_NOTIFY)MFDReceive,
		1
	);

	FltFreeSecurityDescriptor(seucirtyDescriptor);
	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = FltStartFiltering(g_CtxFilter.pFilter);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	return status;

_RET:
	if (NULL != g_CtxFilter.pServerPort)
	{
		FltCloseCommunicationPort(g_CtxFilter.pServerPort);
		g_CtxFilter.pServerPort = NULL;
	}

	if (NULL != g_CtxFilter.pFilter)
	{
		FltUnregisterFilter(g_CtxFilter.pFilter);
		g_CtxFilter.pFilter = NULL;
	}

	return status;
}