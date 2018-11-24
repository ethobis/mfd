#include "mfd_handler.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MFDCreatePreRoutine)
#pragma alloc_text(PAGE, MFDCleanupPreRoutine)
#pragma alloc_text(PAGE, MFDCreatePostRoutine)
#endif

//
// PRE 콜백 루틴
//

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDCreatePreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS FilterRet = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	return FilterRet;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDCleanupPreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS FilterRet = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	return FilterRet;
}

//
// POST 콜백 루틴
//

FLT_POSTOP_CALLBACK_STATUS FLTAPI MFDCreatePostRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	FLT_POSTOP_CALLBACK_STATUS FilterRet = FLT_POSTOP_FINISHED_PROCESSING;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FilterRet;
}
