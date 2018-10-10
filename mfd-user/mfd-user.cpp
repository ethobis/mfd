#include <stdio.h>
#include <Windows.h>
#include <process.h>
#include <fltuser.h>
#include "..\mfd-common\mfd_common.h"

#define FILTER_REQUEST_COUNT 5
#define FILTER_THREAD_COUNT 2
#define FILTER_MAX_THREAD_COUNT 64

typedef struct _FILTER_THREAD_CONTEXT
{
	HANDLE hPort;
	HANDLE hCompletion;
}FILTER_THREAD_CONTEXT, *PFILTER_THREAD_CONTEXT;

UINT WINAPI
FilterWorkThread(
	_In_ PVOID FltWorkThreadContext
)
{
	DWORD dwRetValue = 0;
	PFILTER_NOTIFICATION pNotification = nullptr;
	FILTER_REPLY_MESSAGE ReplyMessage = { 0, };
	PFILTER_MESSAGE pMessage = nullptr;
	LPOVERLAPPED pOvlp = nullptr;
	BOOL bRetValue = FALSE;
	DWORD dwOutputSize = 0;
	HRESULT hr;
	ULONG_PTR ulptrKey = 0;

	PFILTER_THREAD_CONTEXT Context = (PFILTER_THREAD_CONTEXT)FltWorkThreadContext;

	while (1)
	{		
		bRetValue = GetQueuedCompletionStatus(
			Context->hCompletion,
			&dwOutputSize,
			&ulptrKey,
			&pOvlp,
			INFINITE
		);

		pMessage = CONTAINING_RECORD(pOvlp, FILTER_MESSAGE, Ovlp);

		if (bRetValue == FALSE)
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			break;
		}

		pNotification = &(pMessage->Notification);

		ReplyMessage.Reply.bReply = TRUE;
		ReplyMessage.ReplyHeader.Status = 0;
		ReplyMessage.ReplyHeader.MessageId = pMessage->Header.MessageId;

		hr = FilterReplyMessage(
			Context->hPort,
			(PFILTER_REPLY_HEADER)&ReplyMessage,
			sizeof(ReplyMessage)
		);

		if (!SUCCEEDED(hr))
		{
			break;
		}

		memset(pMessage, 0, sizeof(FILTER_MESSAGE));

		hr = FilterGetMessage(
			Context->hPort,
			&pMessage->Header,
			FIELD_OFFSET(FILTER_MESSAGE, Ovlp),
			&pMessage->Ovlp
		);

		if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
			free(pMessage);
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
	HANDLE hPort = nullptr;
	HANDLE hCompletion = nullptr;
	DWORD dwThreadCount = FILTER_THREAD_COUNT;
	DWORD dwRequestCount = FILTER_REQUEST_COUNT;
	HANDLE hThread[FILTER_MAX_THREAD_COUNT];
	DWORD dwThreadId = 0;
	FILTER_THREAD_CONTEXT Context = { nullptr, };
	PFILTER_MESSAGE pMessage = nullptr;
	DWORD dwRetValue = 0;

	hr = FilterConnectCommunicationPort(
		FILTER_NAME,
		0,
		nullptr,
		0,
		nullptr,
		&hPort
	);

	if (IS_ERROR(hr))
	{
		hr = FilterConnectCommunicationPort(
			FILTER_NAME,
			0,	
			nullptr,
			0,
			nullptr,
			&hPort
		);

		if (IS_ERROR(hr))
		{
			goto _RET;
		}
	}

	hCompletion = CreateIoCompletionPort(
		hPort,
		nullptr,
		0,
		dwThreadCount
	);

	if (hCompletion == nullptr)
	{
		goto _RET;
	}

	Context.hPort = hPort;
	Context.hCompletion = hCompletion;

	for (ulIndex = 0; ulIndex < dwThreadCount; ++ulIndex)
	{
		hThread[ulIndex] = (HANDLE)_beginthreadex(
			nullptr,
			0,
			FilterWorkThread,
			&Context,
			0,
			(unsigned int*)dwThreadId
		);

		if (hThread[ulIndex] == nullptr)
		{
			goto _RET;
		}

		for (ulRequestIndex = 0; ulRequestIndex < dwRequestCount; ++ulRequestIndex)
		{
			pMessage = (PFILTER_MESSAGE)malloc(sizeof(FILTER_MESSAGE));

			if (pMessage == nullptr)
			{
				goto _RET;
			}

			memset(pMessage, 0, sizeof(FILTER_MESSAGE));
			memset(&(pMessage->Ovlp), 0, sizeof(OVERLAPPED));

			hr = FilterGetMessage(
				hPort,
				&pMessage->Header,
				FIELD_OFFSET(FILTER_MESSAGE, Ovlp),
				&pMessage->Ovlp
			);

			if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
			{
				free(pMessage);
				goto _RET;
			}
		}
	}

	hr = S_OK;
	WaitForMultipleObjectsEx(ulIndex, hThread, TRUE, INFINITE, FALSE);
	return 0;

_RET:
	if (nullptr != hPort)
	{
		CloseHandle(hPort);
		hPort = nullptr;
	}

	if (nullptr != hCompletion)
	{
		CloseHandle(hCompletion);
		hCompletion = nullptr;
	}

	if (pMessage != nullptr)
	{
		free(pMessage);
		pMessage = nullptr;
	}

	return 0;
}