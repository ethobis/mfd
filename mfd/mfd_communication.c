#include "mfd_communication.h"
#include "mfd_context.h"

#include "..\mfd-common\mfd_common.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MFDSendAbortToUser)
#endif

extern FILTER_CONTEXT g_CtxFilter;

NTSTATUS MFDSendAbortToUser(
	_In_ ULONG ScanThreadId,
	_In_ LONGLONG ScanId
)
{
	FILTER_MESSAGE FilterMessage;
	LARGE_INTEGER timeOut = { 0, };
	ULONG ulReplyLength = 0;

	PAGED_CODE();
	
	FilterMessage.Type = FilterMessageAbortScanning;
	FilterMessage.ScanThreadId = ScanThreadId;
	FilterMessage.ScanId = ScanId;

	timeOut.QuadPart = -10000000 * 1;

	return FltSendMessage(
		g_CtxFilter.pFilter,
		&g_CtxFilter.pAbortClientPort,
		&FilterMessage,
		sizeof(FILTER_MESSAGE),
		NULL,
		&ulReplyLength,
		&timeOut
	);
}