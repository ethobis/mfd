#include "mfd-user.h"

#define  USER_SCAN_COUNT 8

BOOLEAN MFDUserAdjustPrivilege(
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

BOOLEAN MFDUserLoad(
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
		if (HRESULT_FROM_WIN32(ERROR_SERVICE_ALREADY_RUNNING) == hr ||
			HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) == hr)
		{
			return TRUE;
		}

		printf("[-] error : failed to load mfd (0x%08X)\n", hr);

		return FALSE;
	}

	return TRUE;
}

VOID MFDUserScanSynchronizedCancel(
	_In_ PMFD_USER_CONTEXT pUserCtx
)
{
	HRESULT hr = S_OK;
	PMFD_THREAD_CONTEXT pThreadCtx = pUserCtx->ThreadCtx;
	INT nIndex = 0;
	HANDLE hScanHandle[USER_SCAN_COUNT] = { 0, };

	//
	// 종료 플래그 설정
	//

	pUserCtx->bFinalized = TRUE;


	//
	// 실시간 검사 프로시저 I/O 취소 및 대기
	//

	for (nIndex = 0; nIndex < USER_SCAN_COUNT; ++nIndex)
	{
		pThreadCtx[nIndex].bAborted = TRUE;
		hScanHandle[nIndex] = pThreadCtx[nIndex].hThreadHandle;
	}

	CancelIoEx(pUserCtx->hConnectionPort, NULL);

	WaitForMultipleObjects(USER_SCAN_COUNT, hScanHandle, TRUE, INFINITE);

	return ;
}

HRESULT MFDUserScanClose(
	_In_ PMFD_USER_CONTEXT pUserCtx
)
{
	HRESULT hr = S_OK;

	if (pUserCtx->hConnectionPort != NULL)
	{
		if (CloseHandle(pUserCtx->hConnectionPort) == FALSE)
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
		}
		pUserCtx->hConnectionPort = NULL;
	}

	if (pUserCtx->hCompletion != NULL)
	{
		if (CloseHandle(pUserCtx->hCompletion) == FALSE)
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
		}
		pUserCtx->hCompletion = NULL;
	}

	return hr;
}

HRESULT MFDUserAbortProcedure(
	_Inout_ PMFD_USER_CONTEXT pUserCtx
)
{
	HRESULT hr = S_OK;
	HANDLE hAbortPort = NULL;
	FILTER_CONNECTION FilterConnection;
	PFILTER_MESSAGE_NOTIFICATION pMessage = NULL;

	PMFD_THREAD_CONTEXT pThreadCtx = NULL;
	FILTER_MESSAGE_REPLY replyMessage = { 0, };

	UNREFERENCED_PARAMETER(pUserCtx);

	FilterConnection.Type = FilterConnectionForAbort;

	hr = FilterConnectCommunicationPort(
		MFD_ABORT_NAME,
		0,
		&FilterConnection,
		sizeof(FILTER_CONNECTION),
		NULL,
		&hAbortPort
	);

	if (FAILED(hr))
	{
		hAbortPort = NULL;
		return hr;
	}

	while (TRUE)
	{
		hr = FilterGetMessage(
			hAbortPort,
			&pMessage->Header,
			FILTER_MESSAGE_NOTIFICATION_SIZE,
			NULL
		);

		if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED))
		{
			hr = S_OK;
			break;
		}
		else if (FAILED(hr))
		{
			continue;
		}

		if (FilterMessageAbortScanning == pMessage->Message.Type)
		{
			hr = MFDGetThreadContectById(GetCurrentThreadId(), pUserCtx, &pThreadCtx);

			if (FAILED(hr))
			{
				return hr;
			}

			EnterCriticalSection(&(pThreadCtx->Lock));

			if (pThreadCtx->ScanId == pMessage->Message.ScanId)
			{
				pThreadCtx->bAborted = TRUE;
			}

			LeaveCriticalSection(&(pThreadCtx->Lock));
		}
		else if (FilterMessageUnloading == pMessage->Message.Type)
		{
			MFDUserScanSynchronizedCancel(pUserCtx);

			memset(&replyMessage, 0, FILTER_MESSAGE_REPLY_SIZE);
			replyMessage.ReplyHeader.MessageId = pMessage->Header.MessageId;
			replyMessage.ThreadId = pThreadCtx->ThreadId;

			hr = FilterReplyMessage(
				pUserCtx->hConnectionPort,
				&replyMessage.ReplyHeader,
				FILTER_MESSAGE_REPLY_SIZE
			);

			if (FAILED(hr))
			{
				break;
			}

			MFDUserScanClose(pUserCtx);

			if (hAbortPort != NULL)
			{
				CloseHandle(hAbortPort);
				hAbortPort = NULL;
			}

			ExitProcess(0);			
		}
	}

	if (hAbortPort != NULL)
	{
		CloseHandle(hAbortPort);
		hAbortPort = NULL;
	}

	return hr;
}

HRESULT MFDGetThreadContectById(
	_In_ UINT ThreadId,
	_In_ PMFD_USER_CONTEXT pUserCtx,
	_Out_ PMFD_THREAD_CONTEXT* pOutThreadCtx
)
{
	INT nIndex = 0;

	for (nIndex = 0; nIndex < USER_SCAN_COUNT; ++nIndex)
	{
		if (pUserCtx->ThreadCtx[nIndex].ThreadId == ThreadId)
		{
			*pOutThreadCtx = (pUserCtx->ThreadCtx + nIndex);
			return S_OK;
		}
	}

	return MAKE_HRESULT(SEVERITY_ERROR, 0, E_FAIL);
}

HRESULT MFDStartScan(
	_In_ PMFD_USER_CONTEXT pUserCtx,
	_In_  PFILTER_MESSAGE_NOTIFICATION pMessage,
	_In_ PMFD_THREAD_CONTEXT pThreadCtx
)
{
	HRESULT hr = S_OK;
	FILTER_COMMAND CommandMessage;
	HANDLE hSectionHandle = NULL;
	ULONG ulRetLength = 0;

	PVOID pvScanAddress = NULL;
	MEMORY_BASIC_INFORMATION memoryBasicInfo = { 0, };
	DWORD dwFlags = 0;

	CommandMessage.Type = FilterCommandCreateSectionForDataScan;
	CommandMessage.ScanId = pMessage->Message.ScanId;
	CommandMessage.ThreadId = pThreadCtx->ThreadId;

	hr = FilterSendMessage(
		pUserCtx->hConnectionPort,
		&CommandMessage,
		sizeof(FILTER_COMMAND),
		&hSectionHandle,
		sizeof(HANDLE),
		&ulRetLength
	);

	if (FAILED(hr))
	{
		return hr;
	}

	pvScanAddress = MapViewOfFile(hSectionHandle, FILE_MAP_READ, 0, 0, 0);

	if (pvScanAddress == NULL)
	{
		goto _RET;
	}

	if (!VirtualQuery(pvScanAddress, &memoryBasicInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		goto _RET;
	}

	//
	// 검사 결과 저장 (클린 파일) 
	//
	CommandMessage.Result = FilterResultClean;

	//// Windows 8 Later
	//if (pMessage->Message.Reason == FilterReasonOpen)
	//{
	//	dwFlags = MEM_UNMAP_WITH_TRANSIENT_BOOST;
	//}

_RET:
	if (pvScanAddress != NULL)
	{
		//UnmapViewOfFileEx(pvScanAddress, dwFlags);
		UnmapViewOfFile(pvScanAddress);
		pvScanAddress = NULL;
	}

	if (hSectionHandle != NULL)
	{
		CloseHandle(hSectionHandle);
		hSectionHandle = NULL;
	}

	CommandMessage.Type = FilterCommandCloseSectionForDataScan;

	return FilterSendMessage(
		pUserCtx->hConnectionPort,
		&CommandMessage,
		sizeof(FILTER_COMMAND),
		NULL,
		0,
		&ulRetLength
	);
}

HRESULT MFDUserScanProcedure(
	_Inout_ PMFD_USER_CONTEXT pUserCtx
)
{
	HRESULT hr = S_OK;
	PMFD_THREAD_CONTEXT pThreadCtx = NULL;

	PFILTER_MESSAGE_NOTIFICATION pMessage = NULL;
	DWORD outBytes = 0;
	ULONG_PTR completionKey = 0;
	LPOVERLAPPED pOvlp = NULL;

	FILTER_MESSAGE_REPLY replyMessage = { 0, };	

	UNREFERENCED_PARAMETER(pUserCtx);

	hr = MFDGetThreadContectById(GetCurrentThreadId(), pUserCtx, &pThreadCtx);

	if (FAILED(hr))
	{
		return hr;
	}

	while (TRUE)
	{
		pMessage = NULL;

		if (!GetQueuedCompletionStatus(pUserCtx->hCompletion, &outBytes, &completionKey, &pOvlp, INFINITE))
		{
			hr = HRESULT_FROM_WIN32(GetLastError());

			if (hr == E_HANDLE)
			{
				hr = S_OK;
			}
			else if (hr == HRESULT_FROM_WIN32(ERROR_ABANDONED_WAIT_0))
			{
				hr = S_OK;
			}

			break;
		}

		pMessage = CONTAINING_RECORD(pOvlp, FILTER_MESSAGE_NOTIFICATION, Ovlp);

		if (pMessage->Message.Type == FilterMessageStartScanning)
		{
			EnterCriticalSection(&(pThreadCtx->Lock));
			pThreadCtx->bAborted = FALSE;
			pThreadCtx->ScanId = pMessage->Message.ScanId;
			LeaveCriticalSection(&(pThreadCtx->Lock));

			memset(&replyMessage, 0, FILTER_MESSAGE_REPLY_SIZE);
			replyMessage.ReplyHeader.MessageId = pMessage->Header.MessageId;
			replyMessage.ThreadId = pThreadCtx->ThreadId;

			hr = FilterReplyMessage(
				pUserCtx->hConnectionPort,
				&replyMessage.ReplyHeader,
				FILTER_MESSAGE_REPLY_SIZE
			);

			if (FAILED(hr))
			{
				break;
			}

			hr = MFDStartScan(pUserCtx, pMessage, pThreadCtx);
		}

		if (pUserCtx->bFinalized)
		{
			break;
		}

		hr = FilterGetMessage(
			pUserCtx->hConnectionPort,
			&pMessage->Header,
			FIELD_OFFSET(FILTER_MESSAGE_NOTIFICATION, Ovlp),
			&pMessage->Ovlp
		);

		if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED))
		{
			break;
		}
		else if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
			break;
		}
	}

	if (pMessage != NULL)
	{
		free(pMessage);
		pMessage = NULL;
	}

	return hr;
}

HRESULT MFDUserInitialize(
	_In_ PMFD_USER_CONTEXT pUserCtx
)
{
	HRESULT hr = S_OK;
	HANDLE hAbortThread = NULL;
	DWORD dwRetValue = 0;
	PMFD_THREAD_CONTEXT pThreadCtx = NULL;
	INT nIndex = 0;
	FILTER_CONNECTION FilterConnection;

	//
	// 사용자 컨텍스트 파라미터 검사
	//

	if (pUserCtx == NULL)
	{
		return MAKE_HRESULT(SEVERITY_ERROR, 0, E_POINTER);
	}

	//
	// 드라이버 로드 권한 설정
	//

	if (MFDUserAdjustPrivilege(L"SeLoadDriverPrivilege", TRUE) == FALSE)
	{
		goto _RET;
	}

	//
	// 드라이버 설치 및 실행
	//

	if (MFDUserLoad(L"mfd") == FALSE)
	{
		goto _RET;
	}	

	//
	// 중단 요청 송/수신 프로시저 생성
	//

	hAbortThread = (HANDLE)_beginthreadex(
		NULL,
		0,
		(_beginthreadex_proc_type)MFDUserAbortProcedure,
		pUserCtx,
		CREATE_SUSPENDED,
		NULL
	);

	if (hAbortThread == NULL)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto _RET;
	}

	//
	// 실시간 검사 컨텍스트 초기화
	//

	pThreadCtx = (PMFD_THREAD_CONTEXT)malloc(sizeof(MFD_THREAD_CONTEXT) * USER_SCAN_COUNT);

	if (pThreadCtx == NULL)
	{
		hr = MAKE_HRESULT(SEVERITY_ERROR, 0, E_OUTOFMEMORY);
		goto _RET;
	}

	memset(pThreadCtx, 0, sizeof(MFD_THREAD_CONTEXT) * USER_SCAN_COUNT);

	//
	// 실시간 검사 프로시저 생성
	//

	for (nIndex = 0; nIndex < USER_SCAN_COUNT; ++nIndex)
	{
		pThreadCtx[nIndex].hThreadHandle = (HANDLE)_beginthreadex(
			NULL,
			0,
			(_beginthreadex_proc_type)MFDUserScanProcedure,
			pUserCtx,
			CREATE_SUSPENDED,
			&pThreadCtx[nIndex].ThreadId
		);

		if (pThreadCtx[nIndex].hThreadHandle == NULL)
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			goto _RET;
		}

		InitializeCriticalSection(&(pThreadCtx[nIndex].Lock));
	}

	//
	// 실시간 검사 프로시저 설정
	//

	FilterConnection.Type = FilterConnectionForScan;

	hr = FilterConnectCommunicationPort(
		MFD_SCAN_NAME,
		0,
		&FilterConnection,
		sizeof(FILTER_CONNECTION),
		NULL,
		&pUserCtx->hConnectionPort
	);

	if (FAILED(hr))
	{
		pUserCtx->hConnectionPort = NULL;
		goto _RET;
	}

	pUserCtx->hCompletion = CreateIoCompletionPort(
		pUserCtx->hConnectionPort,
		NULL,
		0,
		USER_SCAN_COUNT
	);

	if (pUserCtx == NULL)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto _RET;
	}

	pUserCtx->ThreadCtx = pThreadCtx;
	pUserCtx->hAbortThreadHandle = hAbortThread;

	//
	// 실시간 검사 프로시저 시작
	//

	for (nIndex = 0; nIndex < USER_SCAN_COUNT; ++nIndex)
	{
		if (ResumeThread(pThreadCtx[nIndex].hThreadHandle) == -1)
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			goto _RET;
		}
	}

	//
	// 중단 요청 송/수신 프로시저 시작
	//

	if (ResumeThread(hAbortThread) == -1)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto _RET;
	}

	//
	// 실시간 검사 프로시저 I/O Completion 등록
	//

	for (nIndex = 0; nIndex < USER_SCAN_COUNT; ++nIndex)
	{
		PFILTER_MESSAGE_NOTIFICATION pMessage =
			(PFILTER_MESSAGE_NOTIFICATION)malloc(sizeof(FILTER_MESSAGE_NOTIFICATION));

		if (pMessage == NULL)
		{
			hr = MAKE_HRESULT(SEVERITY_ERROR, 0, E_OUTOFMEMORY);
			goto _RET;
		}

		memset(&pMessage->Ovlp, 0, sizeof(OVERLAPPED));

		hr = FilterGetMessage(
			pUserCtx->hConnectionPort,
			&pMessage->Header,
			FIELD_OFFSET(FILTER_MESSAGE_NOTIFICATION, Ovlp),
			&pMessage->Ovlp
		);

		if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
			hr = S_OK;
		}
		else
		{
			free(pMessage);
			goto _RET;
		}
	}

	return hr;

_RET:
	if (pUserCtx->hCompletion != NULL)
	{
		CloseHandle(pUserCtx->hCompletion);
		pUserCtx->hCompletion = NULL;
	}

	if (pUserCtx->hConnectionPort != NULL)
	{
		CloseHandle(pUserCtx->hConnectionPort);
		pUserCtx->hConnectionPort = NULL;
	}

	if (pThreadCtx != NULL)
	{
		for (nIndex = 0; nIndex < USER_SCAN_COUNT; ++nIndex)
		{
			if (pThreadCtx[nIndex].hThreadHandle != NULL)
			{
				CloseHandle(pThreadCtx[nIndex].hThreadHandle);
				pThreadCtx[nIndex].hThreadHandle = NULL;
			}

			DeleteCriticalSection(&(pThreadCtx[nIndex].Lock));
		}

		free(pThreadCtx);
		pThreadCtx = NULL;
	}

	if (hAbortThread != NULL)
	{
		CloseHandle(hAbortThread);
		hAbortThread = NULL;
	}

	return hr;
}

HRESULT MFDUserFinalize(
	_In_ PMFD_USER_CONTEXT pUserCtx
)
{
	HRESULT hr = S_OK;
	PMFD_THREAD_CONTEXT pThreadCtx = pUserCtx->ThreadCtx;
	INT nIndex = 0;
	HANDLE hScanHandle[USER_SCAN_COUNT] = { 0, };

	//
	// 실시간 검사 프로시저 파라미터 검사
	//

	if (pThreadCtx == NULL)
	{
		return MAKE_HRESULT(SEVERITY_ERROR, 0, E_NOTIMPL);			
	}

	MFDUserScanSynchronizedCancel(pUserCtx);

	//
	// 중단 요청 송/수신 프로시저 정리
	//

	if (pUserCtx->hAbortThreadHandle != NULL)
	{
		CloseHandle(pUserCtx->hAbortThreadHandle);
		pUserCtx->hAbortThreadHandle = NULL;
	}
	
	//
	// 실시간 감시 프로시저 정리
	//

	hr = MFDUserScanClose(pUserCtx);

	for (nIndex = 0; nIndex < USER_SCAN_COUNT; ++nIndex)
	{
		if (pThreadCtx[nIndex].hThreadHandle != NULL)
		{
			CloseHandle(pThreadCtx[nIndex].hThreadHandle);
			pThreadCtx[nIndex].hThreadHandle = NULL;
		}

		DeleteCriticalSection(&(pThreadCtx[nIndex].Lock));
	}

	free(pThreadCtx);
	pThreadCtx = NULL;

	//
	// 드라이버 종료 및 제거
	//

	if (MFDUserUnload(L"mfd") == FALSE)
	{
		hr = S_FALSE;
	}

	return hr;
}

BOOLEAN MFDUserUnload(
	_In_ PWCHAR pwszModuleName
)
{
	wchar_t pwszCommand[100] = { 0, };
	HRESULT hr = S_OK;

	hr = FilterUnload(pwszModuleName);

	if (hr != S_OK)
	{
		printf("[-] error : failed to unload mfd (0x%08X)\n", hr);
		return FALSE;
	}

	swprintf_s(pwszCommand, L"%s .\\%s.inf", L"DefaultUninstall 128", pwszModuleName);
	InstallHinfSectionW(NULL, NULL, pwszCommand, 0);

	return TRUE;
}

int main(
	int argc,
	char** argv
)
{
	int nRet = 0;
	UCHAR uchChar = 0;
	HRESULT hr = S_OK;
	MFD_USER_CONTEXT UserContext = { 0, };

	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	//
	// 엔진 초기화 및 시작
	//

	hr = MFDUserInitialize(&UserContext);

	if (FAILED(hr))
	{
		printf("[-] error : failed to initialize mfd.\n");
		nRet = -1;
		goto _RET;
	}

	printf("[+] succeed to initialize mfd.\n");

	//
	// 사용자 입력 대기
	//

	while (TRUE)
	{
		printf("press 'q' to quit: ");
		uchChar = (UCHAR)getchar();
		if (uchChar == 'q')
		{
			break;
		}
	}

_RET:
	//
	// 엔진 종료 및 정리
	//

	if (MFDUserFinalize(&UserContext) == FALSE)
	{
		printf("[-] error : failed to finalize mfd.\n");
		nRet = -1;
	}

	return nRet;
}