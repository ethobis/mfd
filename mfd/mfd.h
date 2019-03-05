#include "mfd_context.h"
#include "mfd_handler.h"

#include "..\mfd-common\mfd_common.h"

NTSTATUS FLTAPI MFDReceive(
	_In_ PVOID pvConnectionCookie,
	_In_ PVOID pvInputBuffer,
	_In_ ULONG ulInputBufferSize,
	_Out_ PVOID pvOutputBuffer,
	_Out_ ULONG ulOutputBufferSize,
	_Out_ PULONG pulRetOutputBufferSize
);

NTSTATUS FLTAPI MFDConnect(
	_In_ PFLT_PORT pClientPort,
	_In_ PVOID pvServerPortCookie,
	_In_ PVOID pvConnectionContext,
	_In_ ULONG ulSizeOfContext,
	_In_ PVOID *pvConnectionCookie
);

VOID FLTAPI MFDDisconnect(
	_In_ PVOID pvConnectionCookie
);

VOID MFDStreamContextCleanup(
	_In_ PFLT_CONTEXT pContext,
	_In_ FLT_CONTEXT_TYPE ContextType
);

VOID MFDInstanceContextCleanup(
	_In_ PFLT_CONTEXT pContext,
	_In_ FLT_CONTEXT_TYPE ContextType
);

NTSTATUS FLTAPI MFDInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID FLTAPI MFDInstanceTeardown(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
);

VOID MFDCloseCommPort(
	_In_ FILTER_CONNECTION_TYPE  ConnectionType
);

NTSTATUS MFDCreateCommPort(
	_In_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
	_In_ FILTER_CONNECTION_TYPE  ConnectionType
);

NTSTATUS FLTAPI DriverUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

DRIVER_INITIALIZE DriverEntry;

CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{
		IRP_MJ_CREATE,
		0,
		MFDCreatePreRoutine,
		MFDCreatePostRoutine
	},
	{
		IRP_MJ_WRITE,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		MFDWritePreRoutine,
		NULL
	},
	{
		IRP_MJ_SET_INFORMATION,
		FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		MFDSetInformationPreRoutine,
		NULL
	},
	{
		IRP_MJ_CLEANUP,
		0,
		MFDCleanupPreRoutine,
		NULL
	},
	{ IRP_MJ_OPERATION_END }
};

FLT_CONTEXT_REGISTRATION FilterContextRegistration[] =
{
	{
		FLT_INSTANCE_CONTEXT,
		0,
		MFDInstanceContextCleanup,
		FILTER_INSTANCE_CONTEXT_SIZE,
		FILTER_INSTANCE_CONTEXT_TAG
	},
	{ 
		FLT_STREAM_CONTEXT,
		0,
		MFDStreamContextCleanup,
		FILTER_STREAM_CONTEXT_SIZE,
		FILTER_STREAM_CONTEXT_TAG
	},
	{
		FLT_STREAMHANDLE_CONTEXT,
		0,
		NULL,
		FILTER_STREAMHANDLE_CONTEXT_SIZE,
		FILTER_STREAMHANDLE_CONTEXT_TAG
	},
	{ FLT_CONTEXT_END }
};

FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0, // FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP
	FilterContextRegistration,
	Callbacks,
	DriverUnload,
	MFDInstanceSetup,
	NULL,
	MFDInstanceTeardown,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};