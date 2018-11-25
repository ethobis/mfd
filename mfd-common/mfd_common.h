#pragma once
#ifdef _KERNEL_MODE
#include <fltkernel.h>
#else
#include <Windows.h>
#include <stdint.h>
#endif

#pragma warning(disable:4302)
#pragma warning(disable:4311)

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define MFD_FILTER_NAME L"\\mfd"

//
// FltSendMessage -> FilterGetMessage
//

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
#define FILTER_MESSAGE_NOTIFICATION_SIZE (sizeof(FILTER_MESSAGE_HEADER) + sizeof(FILTER_MESSAGE))
#endif

//
// FilterReplyMessage -> Completion of FltSendMessage 
//

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
#define FILTER_MESSAGE_REPLY_SIZE (sizeof(FILTER_REPLY_HEADER) + sizeof(USER_MESSAGE))
#endif

//
// Kernel Mode Filtering Context
//

#ifdef _KERNEL_MODE
typedef struct _FILTER_CONTEXT
{
	PFLT_FILTER pFilter;
	PFLT_PORT pServerPort;
	PFLT_PORT pClientPort;
}FILTER_CONTEXT, *PFILTER_CONTEXT;

typedef struct _FILTER_IO_CONTEXT
{
	ULONG ProcessId;
	WCHAR FilePath[MAX_PATH];
}FILTER_IO_CONTEXT, *PFILTER_IO_CONTEXT;

typedef struct _FILTER_STREAMHANDLE_CONTEXT
{
	FILTER_IO_CONTEXT FilterIoContext;
}FILTER_STREAMHANDLE_CONTEXT, *PFILTER_STREAMHANDLE_CONTEXT;

typedef struct _FILTER_STREAM_CONTEXT
{
	FILTER_IO_CONTEXT FilterIoContext;
}FILTER_STREAM_CONTEXT, *PFILTER_STREAM_CONTEXT;
#endif