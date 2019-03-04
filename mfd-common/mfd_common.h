#pragma once
#ifdef _KERNEL_MODE
#include <fltkernel.h>
#else
#include <stdio.h>
#include <Windows.h>
#include <process.h>
#include <stdint.h>

#include <fltUser.h>
#pragma comment(lib, "fltlib.lib")

#include "Setupapi.h"
#pragma comment(lib, "Setupapi.lib")
#endif

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

//
// Filter <-> User Connection
//

#define MFD_SCAN_NAME L"\\mfdScan"
#define MFD_ABORT_NAME L"\\mfdAbort"
#define MFD_QUERY_NAME L"\\mfdQuery"

typedef enum _FILTER_MESSAGE_TYPE
{
	FilterMessageStartScanning,
	FilterMessageAbortScanning,
	FilterMessageUnloading	
}FILTER_MESSAGE_TYPE;

typedef enum _FILTER_COMMAND_TYPE
{
	FilterCommandIsFileModified,
	FilterCommandCreateSectionForDataScan,
	FilterCommandCloseSectionForDataScan
}FILTER_COMMAND_TYPE;

typedef enum _FILTER_REASON_TYPE
{
	FilterReasonOpen,
	FilterReasonCleanup
}FILTER_REASON_TYPE;

typedef enum _FILTER_RESULT_TYPE
{
	FilterResultUndetermined,
	FilterResultInfected,
	FilterResultClean
}FILTER_RESULT_TYPE;

typedef enum _FILTER_CONNECTION_TYPE
{
	FilterConnectionForScan = 1,
	FilterConnectionForAbort,
	FilterConnectionForQuery
}FILTER_CONNECTION_TYPE, *PFILTER_CONNECTION_TYPE;

typedef struct _FILTER_CONNECTION
{
	FILTER_CONNECTION_TYPE Type;
}FILTER_CONNECTION, *PFILTER_CONNECTION;

//
// FilterSendMessage -> FltMessageNotify Routine
//

typedef struct _FILTER_COMMAND
{
	FILTER_COMMAND_TYPE Type;
	LONGLONG ScanId;
	ULONG ThreadId;
	HANDLE FileHandle;
	FILTER_RESULT_TYPE Result;
}FILTER_COMMAND, *PFILTER_COMMAND;

//
// FltSendMessage -> FilterGetMessage
//

typedef struct _FILTER_MESSAGE
{
	FILTER_MESSAGE_TYPE Type;
	FILTER_REASON_TYPE Reason;
	LONGLONG ScanId;
	ULONG ScanThreadId;
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

#ifndef _KERNEL_MODE
typedef struct _FILTER_MESSAGE_REPLY
{
	FILTER_REPLY_HEADER ReplyHeader;
	ULONG ThreadId;
}FILTER_MESSAGE_REPLY, *PFILTER_MESSAGE_REPLY;
#define FILTER_MESSAGE_REPLY_SIZE (sizeof(FILTER_REPLY_HEADER) + sizeof(ULONG))
#endif