#include "mfd.h"
#include "mfd_handler.h"
#include "mfd_communication.h"

#include <ntimage.h>
#include "Zydis/Zydis.h"
#include "..\mfd-common\mfd_undocument.h"


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MFDConnect)
#pragma alloc_text(PAGE, MFDReceive)
#pragma alloc_text(PAGE, MFDDisconnect)
#pragma alloc_text(PAGE, MFDInstanceSetup)
#pragma alloc_text(PAGE, MFDInstanceTeardown)
#pragma alloc_text(PAGE, MFDCreateCommPort)
#pragma alloc_text(PAGE, MFDCloseCommPort)
#pragma alloc_text(PAGE, DriverUnload)
#endif

FILTER_CONTEXT g_CtxFilter = { 0, };

NTSTATUS FLTAPI MFDConnect(
	_In_ PFLT_PORT pClientPort,
	_In_ PVOID pvServerPortCookie,
	_In_ PVOID pvConnectionContext,
	_In_ ULONG ulSizeOfContext,
	_In_ PVOID *pvConnectionCookie
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PFILTER_CONNECTION pConnection = (PFILTER_CONNECTION)pvConnectionContext;
	PFILTER_CONNECTION_TYPE ConnectionType = NULL;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(pvServerPortCookie);
	UNREFERENCED_PARAMETER(ulSizeOfContext);

	if (pConnection == NULL)
	{
		return STATUS_INVALID_PARAMETER_3;
	}

	ConnectionType = (PFILTER_CONNECTION_TYPE)ExAllocatePoolWithTag(
		PagedPool,
		sizeof(FILTER_CONNECTION_TYPE),
		FILTER_CONNECTION_TAG
	);

	if (ConnectionType == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto _RET;
	}

	*ConnectionType = pConnection->Type;
	
	switch (pConnection->Type)
	{
	case FilterConnectionForScan:
		g_CtxFilter.pScanClientPort = pClientPort;		
		break;
	case FilterConnectionForAbort:
		g_CtxFilter.pAbortClientPort = pClientPort;
		break;
	case FilterConnectionForQuery:
		g_CtxFilter.pQueryClientPort = pClientPort;
		break;
	default:
		status = STATUS_INVALID_PARAMETER_3;
		goto _RET;
	}

	*pvConnectionCookie = ConnectionType;

	return status;

_RET:
	if (ConnectionType != NULL)
	{
		ExFreePoolWithTag(ConnectionType, FILTER_CONNECTION_TAG);
		ConnectionType = NULL;
	}

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
	PFILTER_CONNECTION_TYPE pConnectionType = (PFILTER_CONNECTION_TYPE)pvConnectionCookie;

	PAGED_CODE();

	if (pConnectionType == NULL)
	{
		return;
	}

	switch (*pConnectionType)
	{
	case FilterConnectionForScan:
		FltCloseClientPort(g_CtxFilter.pFilter, &g_CtxFilter.pScanClientPort);
		g_CtxFilter.pScanClientPort = NULL;
		break;
	case FilterConnectionForAbort:
		FltCloseClientPort(g_CtxFilter.pFilter, &g_CtxFilter.pAbortClientPort);
		g_CtxFilter.pAbortClientPort = NULL;
		break;
	case FilterConnectionForQuery:
		FltCloseClientPort(g_CtxFilter.pFilter, &g_CtxFilter.pQueryClientPort);
		g_CtxFilter.pQueryClientPort = NULL;
		break;
	default:
		return;
	}

	ExFreePoolWithTag(pConnectionType, FILTER_CONNECTION_TAG);
	pConnectionType = NULL;

	return;
}

VOID MFDStreamContextCleanup(
	_In_ PFLT_CONTEXT pContext,
	_In_ FLT_CONTEXT_TYPE ContextType
)
{
	UNREFERENCED_PARAMETER(pContext);
	UNREFERENCED_PARAMETER(ContextType);

	return;
}

VOID MFDInstanceContextCleanup(
	_In_ PFLT_CONTEXT pContext,
	_In_ FLT_CONTEXT_TYPE ContextType
)
{
	UNREFERENCED_PARAMETER(pContext);
	UNREFERENCED_PARAMETER(ContextType);

	return;
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

VOID MFDCloseCommPort(
	_In_ FILTER_CONNECTION_TYPE  ConnectionType
)
{
	PFLT_PORT pServerPort = NULL;

	PAGED_CODE();

	switch (ConnectionType)
	{
	case FilterConnectionForScan:
		pServerPort = g_CtxFilter.pScanServerPort;
		break;
	case FilterConnectionForAbort:
		pServerPort = g_CtxFilter.pAbortServerPort;
		break;
	case FilterConnectionForQuery:
		pServerPort = g_CtxFilter.pQueryServerPort;
		break;
	}

	if (pServerPort != NULL)
	{
		FltCloseCommunicationPort(pServerPort);
		pServerPort = NULL;
	}

	return;
}

NTSTATUS MFDCreateCommPort(
	_In_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
	_In_ FILTER_CONNECTION_TYPE  ConnectionType
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PCWSTR pcwPortName = NULL;
	PFLT_PORT* pServerPort = NULL;
	UNICODE_STRING uniPortName = { 0, };
	OBJECT_ATTRIBUTES oa = { 0, };

	PAGED_CODE();

	switch (ConnectionType)
	{
	case FilterConnectionForScan:
		pcwPortName = MFD_SCAN_NAME;
		pServerPort = &g_CtxFilter.pScanServerPort;
		break;
	case FilterConnectionForAbort:
		pcwPortName = MFD_ABORT_NAME;
		pServerPort = &g_CtxFilter.pAbortServerPort;
		break;
	case FilterConnectionForQuery:
		pcwPortName = MFD_QUERY_NAME;
		pServerPort = &g_CtxFilter.pQueryServerPort;
		break;
	default:
		return STATUS_INVALID_PARAMETER;
	}

	RtlInitUnicodeString(&uniPortName, pcwPortName);
	InitializeObjectAttributes(
		&oa,
		&uniPortName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		pSecurityDescriptor
	);

	status = FltCreateCommunicationPort(
		g_CtxFilter.pFilter,
		pServerPort,
		&oa,
		NULL,
		(PFLT_CONNECT_NOTIFY)MFDConnect,
		(PFLT_DISCONNECT_NOTIFY)MFDDisconnect,
		(PFLT_MESSAGE_NOTIFY)MFDReceive,
		1
	);

	return status;
}

NTSTATUS FLTAPI DriverUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	NTSTATUS status = STATUS_SUCCESS;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(Flags);

	MFDCloseCommPort(FilterConnectionForScan);
	MFDCloseCommPort(FilterConnectionForAbort);
	MFDCloseCommPort(FilterConnectionForQuery);

	if (g_CtxFilter.pFilter != NULL)
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
	PSECURITY_DESCRIPTOR seucirtyDescriptor = NULL;

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
	
	status = MFDCreateCommPort(seucirtyDescriptor, FilterConnectionForScan);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = MFDCreateCommPort(seucirtyDescriptor, FilterConnectionForAbort);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = MFDCreateCommPort(seucirtyDescriptor, FilterConnectionForQuery);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	FltFreeSecurityDescriptor(seucirtyDescriptor);

	status = FltStartFiltering(g_CtxFilter.pFilter);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	return status;

_RET:
	MFDCloseCommPort(FilterConnectionForScan);
	MFDCloseCommPort(FilterConnectionForAbort);
	MFDCloseCommPort(FilterConnectionForQuery);
	
	if (g_CtxFilter.pFilter != NULL)
	{
		FltUnregisterFilter(g_CtxFilter.pFilter);
		g_CtxFilter.pFilter = NULL;
	}

	return status;
}