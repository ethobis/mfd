#include "mfd_thread_notify.h"

ACTIVE_THREAD_HEAD ActiveThread = { 0, };

void
MFDInsertActiveThread(
	_In_ PACTIVE_THREAD pActiveThread
)
{
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&ActiveThread.Resource, true);

	InsertTailList(&ActiveThread.ActiveThreadListHead, &pActiveThread->ActiveThreadList);
	ActiveThread.NumberOfActiveThread++;

	ExReleaseResourceLite(&ActiveThread.Resource);
	KeLeaveCriticalRegion();

	return;
}

PACTIVE_THREAD
MFDDeleteActiveThread(
	_In_ ULONG_PTR ulptrThreadId
)
{
	PLIST_ENTRY pThreadListEntry = nullptr;
	PACTIVE_THREAD pSearchActiveThread = nullptr;
	PACTIVE_THREAD pRetActiveThread = nullptr;

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&ActiveThread.Resource, true);

	if (IsListEmpty(&ActiveThread.ActiveThreadListHead))
	{
		goto _RET;
	}

	for (pThreadListEntry = ActiveThread.ActiveThreadListHead.Flink;
		pThreadListEntry && (pThreadListEntry != &ActiveThread.ActiveThreadListHead); pThreadListEntry = pThreadListEntry->Flink)
	{
		pSearchActiveThread = CONTAINING_RECORD(pThreadListEntry, ACTIVE_THREAD, ActiveThreadList);

		if (pSearchActiveThread->ulptrThreadId == ulptrThreadId)
		{
			(pThreadListEntry->Blink)->Flink = pThreadListEntry->Flink;
			(pThreadListEntry->Flink)->Blink = pThreadListEntry->Blink;
			pRetActiveThread = pSearchActiveThread;
			ActiveThread.NumberOfActiveThread--;
			break;
		}
	}

_RET:
	ExReleaseResourceLite(&ActiveThread.Resource);
	KeLeaveCriticalRegion();
	return pRetActiveThread;
}

void
MFDDeleteAllThread(void)
{
	PLIST_ENTRY pDeleteActiveThreadList = nullptr;
	PACTIVE_THREAD pDeleteActiveThread = nullptr;

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&ActiveThread.Resource, true);

	if (IsListEmpty(&ActiveThread.ActiveThreadListHead))
	{
		goto _RET;
	}

	pDeleteActiveThreadList = RemoveHeadList(&ActiveThread.ActiveThreadListHead);

	do
	{
		if (nullptr != pDeleteActiveThreadList)
		{
			pDeleteActiveThread = CONTAINING_RECORD(pDeleteActiveThreadList, ACTIVE_THREAD, ActiveThreadList);

			if (nullptr != pDeleteActiveThread)
			{
				ExFreePool(pDeleteActiveThread);
				pDeleteActiveThread = nullptr;
			}
		}
		pDeleteActiveThreadList = RemoveHeadList(&ActiveThread.ActiveThreadListHead);
	} while (pDeleteActiveThreadList && (pDeleteActiveThreadList != &ActiveThread.ActiveThreadListHead));

_RET:
	ExReleaseResourceLite(&ActiveThread.Resource);
	KeLeaveCriticalRegion();
	return ;
}

void
MFDThreadNotifyRoutine(
	_In_ HANDLE hProcessId,
	_In_ HANDLE hThreadId,
	_In_ BOOLEAN bCreate
)
{
	PACTIVE_THREAD pActiveThread = nullptr;

	UNREFERENCED_PARAMETER(hProcessId);


	if (bCreate)
	{
		pActiveThread = (PACTIVE_THREAD)ExAllocatePool(NonPagedPool, sizeof(ACTIVE_THREAD));

		if (nullptr == pActiveThread)
		{
			goto _RET;
		}

		RtlZeroMemory(pActiveThread, sizeof(ACTIVE_THREAD));
		pActiveThread->ulptrThreadId = (ULONG_PTR)hThreadId;
		MFDInsertActiveThread(pActiveThread);
	}
	else
	{
		pActiveThread = MFDDeleteActiveThread((ULONG_PTR)hThreadId);

		if (nullptr != pActiveThread)
		{
			ExFreePool(pActiveThread);
			pActiveThread = nullptr;
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

	if (nullptr == pvThreadNotifyRoutine)
	{
		goto _RET;
	}

	status = PsSetCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)pvThreadNotifyRoutine);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	InitializeListHead(&ActiveThread.ActiveThreadListHead);
	ExInitializeResourceLite(&ActiveThread.Resource);

_RET:
	return status;
}

NTSTATUS
MFDRemoveThreadNotifyRoutine(
	_In_ PVOID pvThreadNotifyRoutine
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (nullptr == pvThreadNotifyRoutine)
	{
		goto _RET;
	}

	status = PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)pvThreadNotifyRoutine);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	ExDeleteResourceLite(&ActiveThread.Resource);

_RET:
	return status;
}