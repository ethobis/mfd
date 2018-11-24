#include <stdio.h>
#include <Windows.h>
#include <process.h>
#include <fltuser.h>
#include "..\mfd-common\mfd_common.h"

#pragma warning(disable:4312)

typedef struct _MFD_USER_THREAD_CONTEXT
{
	HANDLE hPort;
	HANDLE hCompletion;
}MFD_USER_THREAD_CONTEXT, *PMFD_USER_THREAD_CONTEXT;

UINT WINAPI MFDUserWorkerThread(
	_In_ PVOID FltWorkThreadContext
)
{
	DWORD dwRetValue = 0;
	PFILTER_MESSAGE_NOTIFICATION pNotification = NULL;
	FILTER_MESSAGE_REPLY ReplyMessage = { 0, };
	PFILTER_MESSAGE pMessage = NULL;
	LPOVERLAPPED pOvlp = NULL;
	BOOL bRet = FALSE;
	DWORD dwOutputSize = 0;
	HRESULT hr;
	ULONG_PTR ulptrKey = 0;

	PMFD_USER_THREAD_CONTEXT pContext = (PMFD_USER_THREAD_CONTEXT)FltWorkThreadContext;

	while (1)
	{		
		bRet = GetQueuedCompletionStatus(
			pContext->hCompletion,
			&dwOutputSize,
			&ulptrKey,
			&pOvlp,
			INFINITE
		);

		pNotification = CONTAINING_RECORD(pOvlp, FILTER_MESSAGE_NOTIFICATION, Ovlp);

		if (bRet == FALSE)
		{
			break;
		}
		
		pMessage = &(pNotification->Message);

		ReplyMessage.Reply.unused = 0;
		ReplyMessage.ReplyHeader.Status = 0;
		ReplyMessage.ReplyHeader.MessageId = pNotification->Header.MessageId;

		hr = FilterReplyMessage(
			pContext->hPort,
			(PFILTER_REPLY_HEADER)&ReplyMessage,
			sizeof(ReplyMessage)
		);

		if (IS_ERROR(hr))
		{			
			break;
		}

		memset(pNotification, 0, sizeof(FILTER_MESSAGE_NOTIFICATION));

		hr = FilterGetMessage(
			pContext->hPort,
			&pNotification->Header,
			FIELD_OFFSET(FILTER_MESSAGE_NOTIFICATION, Ovlp),
			&pNotification->Ovlp
		);

		if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
			free(pNotification);
			pNotification = NULL;
			break;
		}
	}

	return 0;
}

int main(int argc, char** argv)
{
	ULONG ulIndex = 0;
	ULONG ulRequestIndex = 0;
	HRESULT hr;
	HANDLE hPort = NULL;
	HANDLE hCompletion = NULL;
	DWORD dwThreadCount = MFD_USER_THREAD_COUNT;
	DWORD dwRequestCount = MFD_USER_REQUEST_COUNT;
	HANDLE hThread[MFD_USER_MAX_THREAD_COUNT];
	DWORD dwThreadId = 0;
	MFD_USER_THREAD_CONTEXT Context = { NULL, };
	PFILTER_MESSAGE_NOTIFICATION pNotification = NULL;
	DWORD dwRetValue = 0;

	hr = FilterConnectCommunicationPort(
		MFD_FILTER_NAME,
		0,
		NULL,
		0,
		NULL,
		&hPort
	);

	if (IS_ERROR(hr) ||
		NULL == hPort)
	{
		goto _RET;
	}

	hCompletion = CreateIoCompletionPort(
		hPort,
		NULL,
		0,
		dwThreadCount
	);

	if (NULL == hCompletion)
	{
		goto _RET;
	}

	Context.hPort = hPort;
	Context.hCompletion = hCompletion;

	for (ulIndex = 0; ulIndex < dwThreadCount; ++ulIndex)
	{
		hThread[ulIndex] = (HANDLE)_beginthreadex(
			NULL,
			0,
			MFDUserWorkerThread,
			&Context,
			0,
			(UINT*)dwThreadId
		);

		if (NULL == hThread[ulIndex])
		{
			break;
		}

		for (ulRequestIndex = 0; ulRequestIndex < dwRequestCount; ++ulRequestIndex)
		{
			pNotification = (PFILTER_MESSAGE_NOTIFICATION)
				malloc(sizeof(FILTER_MESSAGE_NOTIFICATION));

			if (NULL == pNotification)
			{
				break;
			}

			memset(pNotification, 0, sizeof(FILTER_MESSAGE_NOTIFICATION));
			memset(&(pNotification->Ovlp), 0, sizeof(OVERLAPPED));

			hr = FilterGetMessage(
				hPort,
				&pNotification->Header,
				FIELD_OFFSET(FILTER_MESSAGE_NOTIFICATION, Ovlp),
				&pNotification->Ovlp
			);

			if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
			{
				free(pNotification);
				pNotification = NULL;
				break;
			}
		}
	}

	hr = S_OK;
	WaitForMultipleObjectsEx(ulIndex, hThread, TRUE, INFINITE, FALSE);
	
	return 0;

_RET:
	if (NULL != hPort)
	{
		CloseHandle(hPort);
		hPort = NULL;
	}

	if (NULL != hCompletion)
	{
		CloseHandle(hCompletion);
		hCompletion = NULL;
	}

	return 0;
}