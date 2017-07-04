#include "mfd_post_handler.h"

FLT_POSTOP_CALLBACK_STATUS
FLTAPI MFDCreatePostHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS fltRetStatus = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return fltRetStatus;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI MFDReadPostHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS fltRetStatus = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return fltRetStatus;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI MFDWritePostHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS fltRetStatus = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return fltRetStatus;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI MFDSetInformationPostHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS fltRetStatus = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return fltRetStatus;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI MFDDeviceControlPostHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS fltRetStatus = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return fltRetStatus;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI MFDInternalDeviceControlPostHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS fltRetStatus = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return fltRetStatus;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI MFDCleanupPostHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS fltRetStatus = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return fltRetStatus;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI MFDPostHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS fltRetStatus = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	
	switch (pData->Iopb->MajorFunction)
	{
	case IRP_MJ_CREATE:
		MFDCreatePostHandler(pData, pFltObjects, pCompletionContext, Flags);
		break;
	case IRP_MJ_READ:
		MFDReadPostHandler(pData, pFltObjects, pCompletionContext, Flags);
		break;
	case IRP_MJ_WRITE:
		MFDWritePostHandler(pData, pFltObjects, pCompletionContext, Flags);
		break;
	case IRP_MJ_DEVICE_CONTROL:
		MFDDeviceControlPostHandler(pData, pFltObjects, pCompletionContext, Flags);
		break;
	case IRP_MJ_INTERNAL_DEVICE_CONTROL:
		MFDInternalDeviceControlPostHandler(pData, pFltObjects, pCompletionContext, Flags);
		break;
	case IRP_MJ_CLEANUP:
		MFDCleanupPostHandler(pData, pFltObjects, pCompletionContext, Flags);
		break;
	}

	return fltRetStatus;
}