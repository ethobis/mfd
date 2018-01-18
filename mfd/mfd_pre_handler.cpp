#include "mfd_pre_handler.h"
#include "..\mfd-common\mfd_common.h"
#include "..\mfd-common\PE32.h"

#include "mfd_thread_notify.h"
#include "mfd_filesystem.h"

extern ACTIVE_THREAD_HEAD ActiveThreadHead;
extern FILTER_INFO g_FilterInfo;

FLT_PREOP_CALLBACK_STATUS
FLTAPI MFDCreatePreHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS fltRetStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	return fltRetStatus;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI MFDReadPreHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS fltRetStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	return fltRetStatus;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI MFDWritePreHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS fltRetStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	return fltRetStatus;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI MFDSetInformationPreHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS fltRetStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	return fltRetStatus;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI MFDDeviceControlPreHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS fltRetStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	return fltRetStatus;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI MFDInternalDeviceControlPreHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS fltRetStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	return fltRetStatus;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI MFDCleanupPreHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS fltRetStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	return fltRetStatus;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI MFDSetSecurityPreHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS fltRetStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	return fltRetStatus;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI MFDPreHandler(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS fltRetStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	switch (pData->Iopb->MajorFunction)
	{
	case IRP_MJ_CREATE:
		fltRetStatus = MFDCreatePreHandler(pData, pFltObjects, pCompletionContext);
		break;
	case IRP_MJ_READ:
		fltRetStatus = MFDReadPreHandler(pData, pFltObjects, pCompletionContext);
		break;
	case IRP_MJ_WRITE:
		fltRetStatus = MFDWritePreHandler(pData, pFltObjects, pCompletionContext);
		break;
	case IRP_MJ_SET_INFORMATION:
		fltRetStatus = MFDSetInformationPreHandler(pData, pFltObjects, pCompletionContext);
		break;
	case IRP_MJ_DEVICE_CONTROL:
		fltRetStatus = MFDDeviceControlPreHandler(pData, pFltObjects, pCompletionContext);
		break;
	case IRP_MJ_INTERNAL_DEVICE_CONTROL:
		fltRetStatus = MFDInternalDeviceControlPreHandler(pData, pFltObjects, pCompletionContext);
		break;
	case IRP_MJ_CLEANUP:
		fltRetStatus = MFDCleanupPreHandler(pData, pFltObjects, pCompletionContext);
		break;
	case IRP_MJ_SET_SECURITY:
		fltRetStatus = MFDSetSecurityPreHandler(pData, pFltObjects, pCompletionContext);
		break;
	}

	return fltRetStatus;
}