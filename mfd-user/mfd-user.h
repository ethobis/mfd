#pragma once
#include "..\mfd-common\mfd_common.h"

#ifndef MAKE_HRESULT
#define MAKE_HRESULT(sev,fac,code) \
    ((HRESULT) (((unsigned long)(sev)<<31) | ((unsigned long)(fac)<<16) | ((unsigned long)(code))) )
#endif

typedef struct _MFD_THREAD_CONTEXT
{
	HANDLE hThreadHandle;
	UINT ThreadId;
	LONGLONG ScanId;
	BOOLEAN bAborted;
	CRITICAL_SECTION Lock;
}MFD_THREAD_CONTEXT, *PMFD_THREAD_CONTEXT;

typedef struct _MFD_USER_CONTEXT
{
	PMFD_THREAD_CONTEXT ThreadCtx;
	HANDLE hAbortThreadHandle;
	BOOLEAN bFinalized;
	HANDLE hConnectionPort;
	HANDLE hCompletion;
}MFD_USER_CONTEXT, *PMFD_USER_CONTEXT;

BOOLEAN MFDUserAdjustPrivilege(
	_In_ PWCHAR pwszPrivilegeName,
	_In_ BOOLEAN bActivation
);

BOOLEAN MFDUserLoad(
	_In_ PWCHAR pwszModuleName
);

VOID MFDUserScanSynchronizedCancel(
	_In_ PMFD_USER_CONTEXT pUserCtx
);

HRESULT MFDUserScanClose(
	_In_ PMFD_USER_CONTEXT pUserCtx
);

HRESULT MFDUserAbortProcedure(
	_Inout_ PMFD_USER_CONTEXT pUserCtx
);

HRESULT MFDGetThreadContectById(
	_In_ UINT ThreadId,
	_In_ PMFD_USER_CONTEXT pUserCtx,
	_Out_ PMFD_THREAD_CONTEXT* pOutThreadCtx
);

HRESULT MFDStartScan(
	_In_ PMFD_USER_CONTEXT pUserCtx,
	_In_  PFILTER_MESSAGE_NOTIFICATION pMessage,
	_In_ PMFD_THREAD_CONTEXT pThreadCtx
);

HRESULT MFDUserScanProcedure(
	_Inout_ PMFD_USER_CONTEXT pUserCtx
);

HRESULT MFDUserInitialize(
	_In_ PMFD_USER_CONTEXT pUserCtx
);

HRESULT MFDUserFinalize(
	_In_ PMFD_USER_CONTEXT pUserCtx
);

BOOLEAN MFDUserUnload(
	_In_ PWCHAR pwszModuleName
);