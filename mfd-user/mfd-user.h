#ifndef __MFD_USER_H__
#define __MFD_USER_H__

#include<Windows.h>
#include<process.h>
#include<fltuser.h>
#include "..\mfd-common\mfd_common.h"

#define FILTER_DEFAULT_REQUEST_COUNT       5
#define FILTER_DEFAULT_THREAD_COUNT        2
#define FILTER_MAX_THREAD_COUNT            64

typedef struct _FILTER_THREAD_CONTEXT
{
	HANDLE hPort;
	HANDLE hCompletion;
}FILTER_THREAD_CONTEXT, *PFILTER_THREAD_CONTEXT;

#ifdef __cplusplus
extern "C" {
#endif

	UINT WINAPI
	FltWorkThread(
		_In_ PVOID FltWorkThreadContext
	);

#ifdef __cplusplus
}
#endif

#endif