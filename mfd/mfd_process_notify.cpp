#include "mfd_process_notify.h"

ACTIVE_PROCESS_HEAD ActiveProcess = { 0, };

void
MFDInsertActiveProcess(
	_In_ PACTIVE_PROCESS pActiveProcess
)
{
	KLOCK_QUEUE_HANDLE hLockHandle;

	KeAcquireInStackQueuedSpinLock(&ActiveProcess.SpinLock, &hLockHandle);
		InsertTailList(&ActiveProcess.ActiveProcessListHead, &pActiveProcess->ActiveProcessList);
		ActiveProcess.NumberOfActiveProcess++;
	KeReleaseInStackQueuedSpinLock(&hLockHandle);

	return;
}

PACTIVE_PROCESS
MFDDeleteActiveProcess(
	_In_ ULONG_PTR ulptrProcessId
)
{
	PLIST_ENTRY pProcessListEntry = nullptr;
	KLOCK_QUEUE_HANDLE hLockHandle;
	PACTIVE_PROCESS pSearchActiveProcess = nullptr;
	PACTIVE_PROCESS pRetActiveProcess = nullptr;	

	KeAcquireInStackQueuedSpinLock(&ActiveProcess.SpinLock, &hLockHandle);

	if (IsListEmpty(&ActiveProcess.ActiveProcessListHead))
	{
		goto _RET;
	}

	for (pProcessListEntry = ActiveProcess.ActiveProcessListHead.Flink;
		pProcessListEntry && (pProcessListEntry != &ActiveProcess.ActiveProcessListHead); pProcessListEntry = pProcessListEntry->Flink)
	{
		pSearchActiveProcess = CONTAINING_RECORD(pProcessListEntry, ACTIVE_PROCESS, ActiveProcessList);

		if (pSearchActiveProcess->ulptrProcessId == ulptrProcessId)
		{
			(pProcessListEntry->Blink)->Flink = pProcessListEntry->Flink;
			(pProcessListEntry->Flink)->Blink = pProcessListEntry->Blink;
			pRetActiveProcess = pSearchActiveProcess;
			ActiveProcess.NumberOfActiveProcess--;
			break;
		}
	}

_RET:
	KeReleaseInStackQueuedSpinLock(&hLockHandle);
	return pRetActiveProcess;
}

void
MFDDeleteAllProcess(void)
{
	KLOCK_QUEUE_HANDLE hLockHandle;
	PLIST_ENTRY pDeleteActiveProcessList = nullptr;
	PACTIVE_PROCESS pDeleteActiveProcess = nullptr;
	
	KeAcquireInStackQueuedSpinLock(&ActiveProcess.SpinLock, &hLockHandle);

	if (IsListEmpty(&ActiveProcess.ActiveProcessListHead))
	{
		goto _RET;
	}

	pDeleteActiveProcessList = RemoveHeadList(&ActiveProcess.ActiveProcessListHead);

	do
	{
		if (nullptr != pDeleteActiveProcessList)
		{
			pDeleteActiveProcess = CONTAINING_RECORD(pDeleteActiveProcessList, ACTIVE_PROCESS, ActiveProcessList);

			if (nullptr != pDeleteActiveProcess)
			{
				ExFreePool(pDeleteActiveProcess);
				pDeleteActiveProcess = nullptr;
			}
		}
		pDeleteActiveProcessList = RemoveHeadList(&ActiveProcess.ActiveProcessListHead);
	} while (pDeleteActiveProcessList && (pDeleteActiveProcessList != &ActiveProcess.ActiveProcessListHead));

_RET:
	KeReleaseInStackQueuedSpinLock(&hLockHandle);
	return;
}

void
MFDProcessNotifyRoutine(
	_In_ HANDLE hParentId,
	_In_ HANDLE hProcessId,
	_In_ BOOLEAN bCreate
)
{
	PACTIVE_PROCESS pActiveProcess = nullptr;

	UNREFERENCED_PARAMETER(hParentId);

	if (bCreate)
	{
		pActiveProcess = (PACTIVE_PROCESS)ExAllocatePool(NonPagedPool, sizeof(ACTIVE_PROCESS));

		if (nullptr == pActiveProcess)
		{
			goto _RET;
		}

		RtlZeroMemory(pActiveProcess, sizeof(ACTIVE_PROCESS));
		pActiveProcess->ulptrProcessId = (ULONG_PTR)hProcessId;
		MFDInsertActiveProcess(pActiveProcess);
	}
	else
	{
		pActiveProcess = MFDDeleteActiveProcess((ULONG_PTR)hProcessId);

		if (nullptr != pActiveProcess)
		{
			ExFreePool(pActiveProcess);
			pActiveProcess = nullptr;
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

	if (nullptr == pvProcessNotifyRoutine)
	{
		goto _RET;
	}

	status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)pvProcessNotifyRoutine, false);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	InitializeListHead(&ActiveProcess.ActiveProcessListHead);
	KeInitializeSpinLock(&ActiveProcess.SpinLock);

_RET:
	return status;
}

NTSTATUS
MFDRemoveProcessNotifyRoutine(
	_In_ PVOID pvProcessNotifyRoutine
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (nullptr == pvProcessNotifyRoutine)
	{
		goto _RET;
	}

	status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)pvProcessNotifyRoutine, true);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

_RET:
	return status;
}