#include "mfd-user.h"

UINT WINAPI
FltWorkThread(
	_In_ PVOID FltWorkThreadContext
	)
{
	DWORD dwRetValue = 0;
	PFILTER_NOTIFICATION pNotification = NULL;
	FILTER_REPLY_MESSAGE ReplyMessage = { 0, };
	PFILTER_MESSAGE pMessage = NULL;
	LPOVERLAPPED pOvlp = NULL;
	BOOLEAN bRetValue = FALSE;
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

		ReplyMessage.Reply.bContinueFileIRP = TRUE;
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
	HANDLE hPort = NULL, hCompletion = NULL;
	DWORD dwThreadCount = FILTER_DEFAULT_THREAD_COUNT;
	DWORD dwRequestCount = FILTER_DEFAULT_REQUEST_COUNT;
	HANDLE hThread[FILTER_MAX_THREAD_COUNT];
	DWORD dwThreadId = 0;
	FILTER_THREAD_CONTEXT Context = { NULL, };
	PFILTER_MESSAGE pMessage = NULL;
	DWORD dwRetValue = 0;

	hr = FilterConnectCommunicationPort(
		FLT_FILTER_NAME,
		0,
		NULL,
		0,
		NULL,
		&hPort
	);

	if (IS_ERROR(hr))
	{
		hr = FilterConnectCommunicationPort(
			FLT_FILTER_NAME,
			0,	
			NULL,
			0,
			NULL,
			&hPort
		);

		if (IS_ERROR(hr))
		{
			goto _RET;
		}
	}

	hCompletion = CreateIoCompletionPort(
		hPort,
		NULL,
		0,
		dwThreadCount
	);

	if (hCompletion == NULL)
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
			FltWorkThread,
			&Context,
			0,
			(unsigned int*)dwThreadId
		);

		if (hThread[ulIndex] == NULL)
		{
			goto _RET;
		}

		for (ulRequestIndex = 0; ulRequestIndex < dwRequestCount; ++ulRequestIndex)
		{
			pMessage = (PFILTER_MESSAGE)malloc(sizeof(FILTER_MESSAGE));

			if (pMessage == NULL)
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

	if (pMessage != NULL)
	{
		free(pMessage);
		pMessage = NULL;
	}

	return 0;
}