#pragma once
#include <fltkernel.h>

//
// PRE 콜백 루틴
//

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDCreatePreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
);

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDWritePreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
);

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDSetInformationPreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
);

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDCleanupPreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
);

//
// POST 콜백 루틴
//

FLT_POSTOP_CALLBACK_STATUS FLTAPI MFDCreatePostRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_In_opt_ PVOID pCompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);