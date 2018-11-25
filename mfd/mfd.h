#include "../mfd-common/mfd_common.h"

EXTERN_C NTSTATUS FLTAPI MFDReceive(
	_In_ PVOID pvConnectionCookie,
	_In_ PVOID pvInputBuffer,
	_In_ ULONG ulInputBufferSize,
	_Out_ PVOID pvOutputBuffer,
	_Out_ ULONG ulOutputBufferSize,
	_Out_ PULONG pulRetOutputBufferSize
);

EXTERN_C NTSTATUS FLTAPI MFDConnect(
	_In_ PFLT_PORT pClientPort,
	_In_ PVOID pvServerPortCookie,
	_In_ PVOID pvConnectionContext,
	_In_ ULONG ulSizeOfContext,
	_In_ PVOID *pvConnectionCookie
);

EXTERN_C VOID FLTAPI MFDDisconnect(
	_In_ PVOID pvConnectionCookie
);

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDPreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
);

FLT_POSTOP_CALLBACK_STATUS FLTAPI MFDPostRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

EXTERN_C NTSTATUS FLTAPI MFDInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

EXTERN_C VOID FLTAPI MFDInstanceTeardown(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
);

EXTERN_C NTSTATUS FLTAPI DriverUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

EXTERN_C NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT pDriverObject,
	_In_ PUNICODE_STRING puniRegistryPath
);

CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{
		IRP_MJ_CREATE,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_READ,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_WRITE,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_QUERY_INFORMATION,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_SET_INFORMATION,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_QUERY_VOLUME_INFORMATION,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_SET_VOLUME_INFORMATION,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_DIRECTORY_CONTROL,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_FILE_SYSTEM_CONTROL,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_DEVICE_CONTROL,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_INTERNAL_DEVICE_CONTROL,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_CLEANUP,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{
		IRP_MJ_SET_SECURITY,
		0,
		MFDPreRoutine,
		MFDPostRoutine
	},
	{ IRP_MJ_OPERATION_END }
};

FLT_CONTEXT_REGISTRATION FilterContextRegistration[] =
{
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