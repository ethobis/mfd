#include "mfd_handler.h"
#include "mfd_context.h"
#include "mfd_communication.h"

#include "../mfd-common/mfd_common.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MFDCreatePreRoutine)
#pragma alloc_text(PAGE, MFDWritePreRoutine)
#pragma alloc_text(PAGE, MFDSetInformationPreRoutine)
#pragma alloc_text(PAGE, MFDCleanupPreRoutine)
#pragma alloc_text(PAGE, MFDCreatePostRoutine)
#endif

extern FILTER_CONTEXT g_CtxFilter;

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

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	PAGED_CODE();

	return FilterRet;	
}

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDWritePreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS FilterRet = FLT_PREOP_SUCCESS_NO_CALLBACK;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	PAGED_CODE();

	return FilterRet;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDSetInformationPreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS FilterRet = FLT_PREOP_SUCCESS_NO_CALLBACK;
	ULONG FileInformationClass = 0;
	PFILE_RENAME_INFORMATION pFileRenameInformation = NULL;
	PFILE_DISPOSITION_INFORMATION pFileDispositionInformation = NULL;
	FILTER_BEHAVIOR_TYPE BehaviorType = FilterBehaviorDeafult;

	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	PAGED_CODE();

	FileInformationClass = pData->Iopb->Parameters.SetFileInformation.FileInformationClass;

	switch (FileInformationClass)
	{
	case FileRenameInformation:
		pFileRenameInformation = (PFILE_RENAME_INFORMATION)pData->Iopb->Parameters.SetFileInformation.InfoBuffer;
		if (pFileRenameInformation != NULL)
		{
			if (pFileRenameInformation->ReplaceIfExists)
			{
				BehaviorType = FilterBehaviorOverwrite;
			}
			else
			{
				BehaviorType = FilterBehaviorRename;
			}
		}
		else
		{
			goto _RET;
		}
		break;
	case FileDispositionInformation:
		pFileDispositionInformation = (PFILE_DISPOSITION_INFORMATION)pData->Iopb->Parameters.SetFileInformation.InfoBuffer;
		if (pFileDispositionInformation != NULL)
		{
			if (FALSE == pFileDispositionInformation->DeleteFile)
			{
				goto _RET;
			}

			BehaviorType = FilterBehaviorDelete;
		}
		else
		{
			goto _RET;
		}
		break;
	default:
		goto _RET;
	}

_RET:
	return FilterRet;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI MFDCleanupPreRoutine(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PVOID *pCompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS FilterRet = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);

	PAGED_CODE();

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

	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pCompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	return FilterRet;
}
