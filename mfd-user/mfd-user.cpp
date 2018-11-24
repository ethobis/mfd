#include <stdio.h>
#include <Windows.h>
#include <process.h>

#include <fltUser.h>
#pragma comment(lib, "fltlib.lib")

#include "Setupapi.h"
#pragma comment(lib, "Setupapi.lib")

#include "..\mfd-common\mfd_common.h"

#pragma warning(disable:4312)
#pragma warning(disable:6387)

typedef struct _MFD_USER_THREAD_CONTEXT
{
	HANDLE hPort;
	HANDLE hCompletion;
}MFD_USER_THREAD_CONTEXT, *PMFD_USER_THREAD_CONTEXT;

BOOL MFDUserAdjustPrivilege(
	_In_ PWCHAR pwszPrivilegeName,
	_In_ BOOLEAN bActivation
)
{
	BOOL bRet = FALSE;
	LUID Luid = { 0, };
	TOKEN_PRIVILEGES TokenPrivileges = { 0, };
	TOKEN_PRIVILEGES OldTokenPrivileges = { 0, };
	DWORD dwPrivilegeSize = sizeof(TOKEN_PRIVILEGES);
	HANDLE hToken = NULL;
	
	if (NULL == pwszPrivilegeName)
	{
		return FALSE;
	}

	if (FALSE == LookupPrivilegeValueW(
		NULL,
		pwszPrivilegeName,
		&Luid))
	{
		goto _RET;
	}

	if (FALSE == OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		goto _RET;
	}

	memset(&TokenPrivileges, 0, sizeof(TOKEN_PRIVILEGES));
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid = Luid;
	TokenPrivileges.Privileges[0].Attributes = 
		bActivation == TRUE ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

	if (FALSE == AdjustTokenPrivileges(
		hToken,
		false, 
		&TokenPrivileges,
		sizeof(TOKEN_PRIVILEGES),
		&OldTokenPrivileges,
		&dwPrivilegeSize))
	{
		goto _RET;
	}

	bRet = TRUE;
	
_RET:
	if (NULL != hToken)
	{
		CloseHandle(hToken);
	}

	return bRet;
}

BOOL MFDUserStart(
	_In_ PWCHAR pwszModuleName
)
{
	wchar_t pwszCommand[100] = { 0, };
	HRESULT hr = S_OK;

	swprintf_s(pwszCommand, L"%s .\\%s.inf", L"DefaultInstall 128", pwszModuleName);
	InstallHinfSectionW(NULL, NULL, pwszCommand, 0);

	hr = FilterLoad(pwszModuleName);

	if (S_OK != hr)
	{
		printf("[-] Error : MFDUserStart => 0x%08X\n", hr);
		return FALSE;
	}

	return TRUE;
}

BOOLEAN MFDUserStop(
	_In_ PWCHAR pwszModuleName
)
{
	wchar_t pwszCommand[100] = { 0, };
	HRESULT hr = S_OK;

	hr = FilterUnload(pwszModuleName);

	if (S_OK != hr)
	{
		printf("[-] Error : MFDUserStop => 0x%08X\n", hr);
		return FALSE;
	}

	swprintf_s(pwszCommand, L"%s .\\%s.inf", L"DefaultUninstall 128", pwszModuleName);
	InstallHinfSectionW(NULL, NULL, pwszCommand, 0);

	return TRUE;
}

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

		printf("Get Message!\n");

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

VOID MFDUserConnect()
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

	return;
}

int main(int argc, char** argv)
{
	const char* pszArgument = NULL;

	if (argc < 2)
	{
		return -1;
	}

	pszArgument = argv[1];

	if (FALSE == MFDUserAdjustPrivilege(L"SeLoadDriverPrivilege", TRUE))
	{
		return -1;
	}

	if (!_stricmp(pszArgument, "start"))
	{
		MFDUserStart(L"mfd");
	}
	else if (!_stricmp(pszArgument, "stop"))
	{
		MFDUserStop(L"mfd");
	}
	else if (!_stricmp(pszArgument, "connect"))
	{
		MFDUserConnect();
	}
	else
	{
		return -1;
	}

	return 0;
}