#pragma once
#ifndef _KERNEL_MODE
#include <Windows.h>
#include <stdint.h>
#else
#include <fltkernel.h>
#endif

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define FILTER_NAME L"\\mfd"
#define FILTER_SIZE 1024

//
// 공용 구조체
//

typedef struct _FILTER_NOTIFICATION
{
	ULONG_PTR ulptrCurrentProcessId;
	WCHAR wchFilePath[MAX_PATH];
}FILTER_NOTIFICATION, *PFILTER_NOTIFICATION;

#ifndef _KERNEL_MODE
typedef struct _FILTER_MESSAGE
{
	FILTER_MESSAGE_HEADER Header;
	FILTER_NOTIFICATION Notification;
	OVERLAPPED Ovlp;
}FILTER_MESSAGE, *PFILTER_MESSAGE;
#endif
typedef struct _FILTER_REPLY
{
	BOOLEAN bReply;
}FILTER_REPLY, *PFILTER_REPLY;

typedef struct _FILTER_REPLY_MESSAGE
{
	FILTER_REPLY_HEADER ReplyHeader;
	FILTER_REPLY Reply;
}FILTER_REPLY_MESSAGE, *PFILTER_REPLY_MESSAGE;

//
// 커널모드 전용 구조체
//

#ifdef _KERNEL_MODE
typedef struct _FILTER_INFO
{
	PFLT_FILTER pFilter;
	PFLT_PORT pServerPort;
	PFLT_PORT pClientPort;
}FILTER_INFO, *PFILTER_INFO;

typedef struct _FILTER_STREAMHANDLE_CONTEXT
{
	ULONG ProcessId;
	PVOID FileObject;
}FILTER_STREAMHANDLE_CONTEXT, *PFILTER_STREAMHANDLE_CONTEXT;
#endif