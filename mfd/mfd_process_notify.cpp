#include "mfd_process_notify.h"

ACTIVE_PROCESS_HEAD ActiveProcessHead = { NULL, };

VOID
MFDInsertActiveProcess(
	_In_ PACTIVE_PROCESS pActiveProcess
)
{
	KLOCK_QUEUE_HANDLE hLockHandle = { 0, };

	KeAcquireInStackQueuedSpinLock(&ActiveProcessHead.SpinLock, &hLockHandle);

	InsertTailList(&ActiveProcessHead.ActiveProcessListHead, &pActiveProcess->ActiveProcessList);
	ActiveProcessHead.NumberOfActiveProcess++;

	KeReleaseInStackQueuedSpinLock(&hLockHandle);

	return;
}

PACTIVE_PROCESS
MFDAcquireActiveProcess(
	_In_ PEPROCESS pActiveProcess,
	_In_ PKLOCK_QUEUE_HANDLE pLockHandle
)
{
	PLIST_ENTRY pProcessListEntry = NULL;
	PACTIVE_PROCESS pSearchActiveProcess = NULL;
	PACTIVE_PROCESS pRetActiveProcess = NULL;

	KLOCK_QUEUE_HANDLE hLockHandle = { 0, };

	KeAcquireInStackQueuedSpinLock(&ActiveProcessHead.SpinLock, &hLockHandle);

	if (IsListEmpty(&ActiveProcessHead.ActiveProcessListHead))
	{
		goto _RET;
	}

	for (pProcessListEntry = ActiveProcessHead.ActiveProcessListHead.Flink;
		pProcessListEntry && (pProcessListEntry != &ActiveProcessHead.ActiveProcessListHead); pProcessListEntry = pProcessListEntry->Flink)
	{
		pSearchActiveProcess = CONTAINING_RECORD(pProcessListEntry, ACTIVE_PROCESS, ActiveProcessList);

		if (pSearchActiveProcess->Process == pActiveProcess)
		{
			pRetActiveProcess = pSearchActiveProcess;
			ActiveProcessHead.bAcquired = TRUE;
			break;
		}
	}

_RET:
	if (NULL == pRetActiveProcess)
	{
		KeReleaseInStackQueuedSpinLock(pLockHandle);
	}

	return pRetActiveProcess;
}

VOID
MFDReleaseActiveProcess(
	_In_ PKLOCK_QUEUE_HANDLE pLockHandle
)
{
	if (ActiveProcessHead.bAcquired)
	{
		ActiveProcessHead.bAcquired = FALSE;
		KeReleaseInStackQueuedSpinLock(pLockHandle);
	}
}

PACTIVE_PROCESS
MFDDeleteActiveProcess(
	_In_ PEPROCESS pDeleteProcess
)
{
	PLIST_ENTRY pProcessListEntry = NULL;
	PACTIVE_PROCESS pSearchActiveProcess = NULL;
	PACTIVE_PROCESS pRetActiveProcess = NULL;
	KLOCK_QUEUE_HANDLE hLockHandle = { 0, };

	KeAcquireInStackQueuedSpinLock(&ActiveProcessHead.SpinLock, &hLockHandle);

	if (IsListEmpty(&ActiveProcessHead.ActiveProcessListHead))
	{
		goto _RET;
	}

	for (pProcessListEntry = ActiveProcessHead.ActiveProcessListHead.Flink;
		pProcessListEntry && (pProcessListEntry != &ActiveProcessHead.ActiveProcessListHead); pProcessListEntry = pProcessListEntry->Flink)
	{
		pSearchActiveProcess = CONTAINING_RECORD(pProcessListEntry, ACTIVE_PROCESS, ActiveProcessList);

		if (pSearchActiveProcess->Process == pDeleteProcess)
		{
			(pProcessListEntry->Blink)->Flink = pProcessListEntry->Flink;
			(pProcessListEntry->Flink)->Blink = pProcessListEntry->Blink;
			pRetActiveProcess = pSearchActiveProcess;
			ActiveProcessHead.NumberOfActiveProcess--;
			break;
		}
	}

_RET:
	KeReleaseInStackQueuedSpinLock(&hLockHandle);
	return pRetActiveProcess;
}

VOID
MFDDeleteAllProcess(VOID)
{
	PLIST_ENTRY pDeleteActiveProcessList = NULL;
	PACTIVE_PROCESS pDeleteActiveProcess = NULL;
	KLOCK_QUEUE_HANDLE hLockHandle = { 0, };

	KeAcquireInStackQueuedSpinLock(&ActiveProcessHead.SpinLock, &hLockHandle);

	if (IsListEmpty(&ActiveProcessHead.ActiveProcessListHead))
	{
		goto _RET;
	}

	pDeleteActiveProcessList = RemoveHeadList(&ActiveProcessHead.ActiveProcessListHead);

	do
	{
		if (NULL != pDeleteActiveProcessList)
		{
			pDeleteActiveProcess = CONTAINING_RECORD(pDeleteActiveProcessList, ACTIVE_PROCESS, ActiveProcessList);

			if (NULL != pDeleteActiveProcess)
			{
				ExFreeToNPagedLookasideList(&ActiveProcessHead.ProcessNPLookasideList, pDeleteActiveProcess);
				pDeleteActiveProcess = NULL;
			}
		}
		pDeleteActiveProcessList = RemoveHeadList(&ActiveProcessHead.ActiveProcessListHead);
	} while (pDeleteActiveProcessList && (pDeleteActiveProcessList != &ActiveProcessHead.ActiveProcessListHead));

_RET:
	KeReleaseInStackQueuedSpinLock(&hLockHandle);
	return;
}

VOID
MFDProcessNotifyRoutine(
	_In_ HANDLE hParentId,
	_In_ HANDLE hProcessId,
	_In_ BOOLEAN bCreate
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PACTIVE_PROCESS pActiveProcess = NULL;
	PEPROCESS pProcessLookupByPid = NULL;

	UNREFERENCED_PARAMETER(hParentId);

	status = PsLookupProcessByProcessId(hProcessId, &pProcessLookupByPid);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	if (bCreate)
	{
		pActiveProcess = (PACTIVE_PROCESS)ExAllocateFromNPagedLookasideList(&ActiveProcessHead.ProcessNPLookasideList);

		if (NULL == pActiveProcess)
		{
			goto _RET;
		}

		RtlZeroMemory(pActiveProcess, sizeof(PACTIVE_PROCESS));
		pActiveProcess->Process = pProcessLookupByPid;
		MFDInsertActiveProcess(pActiveProcess);
	}
	else
	{
		pActiveProcess = MFDDeleteActiveProcess(pProcessLookupByPid);

		if (NULL != pActiveProcess)
		{
			ExFreeToNPagedLookasideList(&ActiveProcessHead.ProcessNPLookasideList, pActiveProcess);
			pActiveProcess = NULL;
		}
	}

_RET:
	return ;
}

NTSTATUS
MFDSetProcessNotifyRoutine(
	_In_ PVOID pvProcessNotifyRoutine
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (NULL == pvProcessNotifyRoutine)
	{
		goto _RET;
	}

	status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)pvProcessNotifyRoutine, FALSE);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	InitializeListHead(&ActiveProcessHead.ActiveProcessListHead);
	KeInitializeSpinLock(&ActiveProcessHead.SpinLock);
	ExInitializeNPagedLookasideList(&ActiveProcessHead.ProcessNPLookasideList, NULL, NULL, 0, sizeof(ACTIVE_PROCESS), 0, 0);

_RET:
	return status;
}

NTSTATUS
MFDRemoveProcessNotifyRoutine(
	_In_ PVOID pvProcessNotifyRoutine
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (NULL == pvProcessNotifyRoutine)
	{
		goto _RET;
	}

	status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)pvProcessNotifyRoutine, TRUE);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	ExDeleteNPagedLookasideList(&ActiveProcessHead.ProcessNPLookasideList);

_RET:
	return status;
}