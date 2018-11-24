#pragma once
#ifdef _KERNEL_MODE
#include <fltkernel.h>
#else
#include <Windows.h>
#include <stdint.h>
#endif

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define MFD_FILTER_NAME L"\\mfd"

#ifndef _KERNEL_MODE
#define MFD_USER_REQUEST_COUNT 5
#define MFD_USER_THREAD_COUNT 2
#define MFD_USER_MAX_THREAD_COUNT 64
#else
typedef struct _FILTER_CONTEXT
{
	PFLT_FILTER pFilter;
	PFLT_PORT pServerPort;
	PFLT_PORT pClientPort;
}FILTER_CONTEXT, *PFILTER_CONTEXT;
#endif

typedef struct _FILTER_MESSAGE
{
	ULONG ProcessId;
	WCHAR FilePath[MAX_PATH];
}FILTER_MESSAGE, *PFILTER_MESSAGE;

#ifndef _KERNEL_MODE
typedef struct _FILTER_MESSAGE_NOTIFICATION
{
	FILTER_MESSAGE_HEADER Header;
	FILTER_MESSAGE Message;
	OVERLAPPED Ovlp;
}FILTER_MESSAGE_NOTIFICATION, *PFILTER_MESSAGE_NOTIFICATION;
#endif

typedef struct _USER_MESSAGE
{
	ULONG unused;
}USER_MESSAGE, *PUSER_MESSAGE;

#ifndef _KERNEL_MODE
typedef struct _FILTER_MESSAGE_REPLY
{
	FILTER_REPLY_HEADER ReplyHeader;
	USER_MESSAGE Reply;
}FILTER_MESSAGE_REPLY, *PFILTER_MESSAGE_REPLY;
#endif