#include "mfd_thread_notify.h"

ACTIVE_THREAD_HEAD ActiveThreadHead = { NULL, };

VOID
MFDInsertActiveThread(
	_In_ PACTIVE_THREAD pActiveThread
)
{
	KLOCK_QUEUE_HANDLE hLockHandle = { 0, };

	KeAcquireInStackQueuedSpinLock(&ActiveThreadHead.SpinLock, &hLockHandle);

	InsertTailList(&ActiveThreadHead.ActiveThreadListHead, &pActiveThread->ActiveThreadList);
	ActiveThreadHead.NumberOfActiveThread++;

	KeReleaseInStackQueuedSpinLock(&hLockHandle);

	return;
}

PACTIVE_THREAD
MFDAcquireActiveThread(
	_In_ PETHREAD DeleteThread,
	_In_ PKLOCK_QUEUE_HANDLE pLockHandle
)
{
	PLIST_ENTRY pThreadListEntry = NULL;
	PACTIVE_THREAD pSearchActiveThread = NULL;
	PACTIVE_THREAD pRetActiveThread = NULL;

	KeAcquireInStackQueuedSpinLock(&ActiveThreadHead.SpinLock, pLockHandle);

	if (IsListEmpty(&ActiveThreadHead.ActiveThreadListHead))
	{
		goto _RET;
	}

	for (pThreadListEntry = ActiveThreadHead.ActiveThreadListHead.Flink;
		pThreadListEntry && (pThreadListEntry != &ActiveThreadHead.ActiveThreadListHead); pThreadListEntry = pThreadListEntry->Flink)
	{
		pSearchActiveThread = CONTAINING_RECORD(pThreadListEntry, ACTIVE_THREAD, ActiveThreadList);

		if (pSearchActiveThread->Thread == DeleteThread)
		{
			pRetActiveThread = pSearchActiveThread;
			ActiveThreadHead.bAcquired = TRUE;
			break;
		}
	}

_RET:
	if (NULL == pRetActiveThread)
	{
		KeReleaseInStackQueuedSpinLock(pLockHandle);
	}

	return pRetActiveThread;
}

VOID
MFDReleaseActiveThread(
	_In_ PKLOCK_QUEUE_HANDLE pLockHandle
)
{
	if (ActiveThreadHead.bAcquired)
	{
		ActiveThreadHead.bAcquired = FALSE;
		KeReleaseInStackQueuedSpinLock(pLockHandle);
	}
	
	return;
}

PACTIVE_THREAD
MFDDeleteActiveThread(
	_In_ PETHREAD DeleteThread
)
{
	PLIST_ENTRY pThreadListEntry = NULL;
	PACTIVE_THREAD pSearchActiveThread = NULL;
	PACTIVE_THREAD pRetActiveThread = NULL;
	KLOCK_QUEUE_HANDLE hLockHandle = { 0, };

	KeAcquireInStackQueuedSpinLock(&ActiveThreadHead.SpinLock, &hLockHandle);

	if (IsListEmpty(&ActiveThreadHead.ActiveThreadListHead))
	{
		goto _RET;
	}

	for (pThreadListEntry = ActiveThreadHead.ActiveThreadListHead.Flink;
		pThreadListEntry && (pThreadListEntry != &ActiveThreadHead.ActiveThreadListHead); pThreadListEntry = pThreadListEntry->Flink)
	{
		pSearchActiveThread = CONTAINING_RECORD(pThreadListEntry, ACTIVE_THREAD, ActiveThreadList);

		if (pSearchActiveThread->Thread == DeleteThread)
		{
			(pThreadListEntry->Blink)->Flink = pThreadListEntry->Flink;
			(pThreadListEntry->Flink)->Blink = pThreadListEntry->Blink;
			pRetActiveThread = pSearchActiveThread;
			ActiveThreadHead.NumberOfActiveThread--;
			break;
		}
	}

_RET:
	KeReleaseInStackQueuedSpinLock(&hLockHandle);
	return pRetActiveThread;
}

VOID
MFDDeleteAllThread(VOID)
{
	PLIST_ENTRY pDeleteActiveThreadList = NULL;
	PACTIVE_THREAD pDeleteActiveThread = NULL;
	KLOCK_QUEUE_HANDLE hLockHandle = { 0, };

	KeAcquireInStackQueuedSpinLock(&ActiveThreadHead.SpinLock, &hLockHandle);

	if (IsListEmpty(&ActiveThreadHead.ActiveThreadListHead))
	{
		goto _RET;
	}

	pDeleteActiveThreadList = RemoveHeadList(&ActiveThreadHead.ActiveThreadListHead);

	do
	{
		if (NULL != pDeleteActiveThreadList)
		{
			pDeleteActiveThread = CONTAINING_RECORD(pDeleteActiveThreadList, ACTIVE_THREAD, ActiveThreadList);

			if (NULL != pDeleteActiveThread)
			{
				ExFreeToNPagedLookasideList(&ActiveThreadHead.ThreadNPLookasideList, pDeleteActiveThread);
				pDeleteActiveThread = NULL;
			}
		}
		pDeleteActiveThreadList = RemoveHeadList(&ActiveThreadHead.ActiveThreadListHead);
	} while (pDeleteActiveThreadList && (pDeleteActiveThreadList != &ActiveThreadHead.ActiveThreadListHead));

_RET:
	KeReleaseInStackQueuedSpinLock(&hLockHandle);
	return ;
}

VOID
MFDThreadNotifyRoutine(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PACTIVE_THREAD pActiveThread = NULL;
	PETHREAD pThreadLookupByTid = NULL;

	UNREFERENCED_PARAMETER(ProcessId);

	status = PsLookupThreadByThreadId(ThreadId, &pThreadLookupByTid);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	if (Create)
	{
		pActiveThread = (PACTIVE_THREAD)ExAllocateFromNPagedLookasideList(&ActiveThreadHead.ThreadNPLookasideList);

		if (NULL == pActiveThread)
		{
			goto _RET;
		}

		RtlZeroMemory(pActiveThread, sizeof(ACTIVE_THREAD));		
		pActiveThread->Thread = pThreadLookupByTid;	
		MFDInsertActiveThread(pActiveThread);
	}
	else
	{
		pActiveThread = MFDDeleteActiveThread(pThreadLookupByTid);

		if (NULL != pActiveThread)
		{
			ExFreeToNPagedLookasideList(&ActiveThreadHead.ThreadNPLookasideList, pActiveThread);
			pActiveThread = NULL;
		}
	}	

_RET:
	return;
}

NTSTATUS
MFDSetThreadNotifyRoutine(
	_In_ PVOID pvThreadNotifyRoutine
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (NULL == pvThreadNotifyRoutine)
	{
		goto _RET;
	}

	status = PsSetCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)pvThreadNotifyRoutine);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	InitializeListHead(&ActiveThreadHead.ActiveThreadListHead);
	KeInitializeSpinLock(&ActiveThreadHead.SpinLock);
	ExInitializeNPagedLookasideList(&ActiveThreadHead.ThreadNPLookasideList, NULL, NULL, 0, sizeof(ACTIVE_THREAD), 0, 0);

_RET:
	return status;
}

NTSTATUS
MFDRemoveThreadNotifyRoutine(
	_In_ PVOID pvThreadNotifyRoutine
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (NULL == pvThreadNotifyRoutine)
	{
		goto _RET;
	}

	status = PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)pvThreadNotifyRoutine);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	ExDeleteNPagedLookasideList(&ActiveThreadHead.ThreadNPLookasideList);

_RET:
	return status;
}