#ifndef __MFD_COMMON_H__
#define __MFD_COMMON_H__

#define FLT_FILTER_NAME L"\\mfd"
#define FLT_BUFFER_SIZE 1024

typedef struct _FILTER_NOTIFICATION
{
	ULONG_PTR ulptrSendBytes;
	ULONG_PTR ulptrCurrentProcessId;
	WCHAR wchFilePath[FLT_BUFFER_SIZE];
}FILTER_NOTIFICATION, *PFILTER_NOTIFICATION;

typedef struct _FILTER_REPLY
{
	BOOLEAN bContinueFileIRP;
}FILTER_REPLY, *PFILTER_REPLY;

#ifdef MFD_USER_MODE
typedef struct _FILTER_MESSAGE
{
	FILTER_MESSAGE_HEADER Header;
	FILTER_NOTIFICATION Notification;
	OVERLAPPED Ovlp;
}FILTER_MESSAGE, *PFILTER_MESSAGE;

typedef struct _FILTER_REPLY_MESSAGE
{
	FILTER_REPLY_HEADER ReplyHeader;
	FILTER_REPLY Reply;
}FILTER_REPLY_MESSAGE, *PFILTER_REPLY_MESSAGE;
#else
typedef struct _FILTER_INFO
{
	PFLT_FILTER pFilter;
	PFLT_PORT pServerPort;
	PFLT_PORT pClientPort;
}FILTER_INFO, *PFILTER_INFO;
#endif 

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif