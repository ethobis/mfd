#ifndef __MFD_THREAD_NOTIFY_H__
#define __MFD_THREAD_NOTIFY_H__

#include <ntifs.h>
#include <ntddk.h>

typedef struct _ACTIVE_THREAD_HEAD
{
	LIST_ENTRY ActiveThreadListHead;
	BOOLEAN bAcquired;
	ERESOURCE Resource;
	ULONG NumberOfActiveThread;
	NPAGED_LOOKASIDE_LIST ThreadNPLookasideList;
}ACTIVE_THREAD_HEAD, *PACTIVE_THREAD_HEAD;

typedef struct _ACTIVE_THREAD
{
	ULONG_PTR ulptrThreadId;
	LIST_ENTRY ActiveThreadList;
	/*
		Add-Context	
	*/
}ACTIVE_THREAD, *PACTIVE_THREAD;

#ifdef __cplusplus
extern "C" {
#endif

	void
	MFDInsertActiveThread(
		_In_ PACTIVE_THREAD pActiveThread
	);

	PACTIVE_THREAD
	MFDDeleteActiveThread(
		_In_ ULONG_PTR ulptrThreadId
	);

	void
	MFDDeleteAllThread(void);

	void
	MFDThreadNotifyRoutine(
		_In_ HANDLE hProcessId,
		_In_ HANDLE hThreadId,
		_In_ BOOLEAN bCreate
	);

	NTSTATUS
	MFDSetThreadNotifyRoutine(
		_In_ PVOID pvThreadNotifyRoutine
	);

	NTSTATUS
	MFDRemoveThreadNotifyRoutine(
		_In_ PVOID pvThreadNotifyRoutine
	);

#ifdef __cplusplus
}
#endif

#endif