#ifndef __MFD_POST_HANDLER_H__
#define __MFD_POST_HANDLER_H__

#pragma warning(push)
#pragma warning(disable:4510)
#pragma warning(disable:4512)
#pragma warning(disable:4610)
#include <fltKernel.h>
#pragma warning(pop)
#pragma optimize("", off)

#ifdef __cplusplus
extern "C" {
#endif

	FLT_POSTOP_CALLBACK_STATUS
	FLTAPI MFDCreatePostHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_In_opt_ PVOID pCompletionContext,
		_In_ FLT_POST_OPERATION_FLAGS Flags
	);
	
	FLT_POSTOP_CALLBACK_STATUS
	FLTAPI MFDDeviceControlPostHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_In_opt_ PVOID pCompletionContext,
		_In_ FLT_POST_OPERATION_FLAGS Flags
	);

	FLT_POSTOP_CALLBACK_STATUS
	FLTAPI MFDInternalDeviceControlPostHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_In_opt_ PVOID pCompletionContext,
		_In_ FLT_POST_OPERATION_FLAGS Flags
	);

	FLT_POSTOP_CALLBACK_STATUS
	FLTAPI MFDCleanupPostHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_In_opt_ PVOID pCompletionContext,
		_In_ FLT_POST_OPERATION_FLAGS Flags
	);

	FLT_POSTOP_CALLBACK_STATUS
	FLTAPI MFDPostHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_In_opt_ PVOID pCompletionContext,
		_In_ FLT_POST_OPERATION_FLAGS Flags
	);

#ifdef __cplusplus
}
#endif

#endif