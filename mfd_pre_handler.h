#ifndef __MFD_PRE_HANDLER_H__
#define __MFD_PRE_HANDLER_H__

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

	FLT_PREOP_CALLBACK_STATUS
	FLTAPI MFDCreatePreHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Out_ PVOID *pCompletionContext
	);

	FLT_PREOP_CALLBACK_STATUS
	FLTAPI MFDReadPreHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Out_ PVOID *pCompletionContext
	);

	FLT_PREOP_CALLBACK_STATUS
	FLTAPI MFDWritePreHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Out_ PVOID *pCompletionContext
	);

	FLT_PREOP_CALLBACK_STATUS
	FLTAPI MFDSetInformationPreHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Out_ PVOID *pCompletionContext
	);

	FLT_PREOP_CALLBACK_STATUS
	FLTAPI MFDDeviceControlPreHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Out_ PVOID *pCompletionContext
	);

	FLT_PREOP_CALLBACK_STATUS
	FLTAPI MFDInternalDeviceControlPreHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Out_ PVOID *pCompletionContext
	);

	FLT_PREOP_CALLBACK_STATUS
	FLTAPI MFDCleanupPreHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Out_ PVOID *pCompletionContext
	);

	FLT_PREOP_CALLBACK_STATUS
	FLTAPI MFDPreHandler(
		_Inout_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Out_ PVOID *pCompletionContext
	);

#ifdef __cplusplus
}
#endif

#endif