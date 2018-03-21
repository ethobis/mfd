#ifndef __MFD_PROCESS_NOTIFY_H__
#define __MFD_PROCESS_NOTIFY_H__

#include <ntifs.h>
#include <ntddk.h>

typedef struct _ACTIVE_PROCESS_HEAD
{
	LIST_ENTRY ActiveProcessListHead;
	BOOLEAN bAcquired;
	KSPIN_LOCK SpinLock;
	ULONG NumberOfActiveProcess;
}ACTIVE_PROCESS_HEAD, *PACTIVE_PROCESS_HEAD;

typedef struct _ACTIVE_PROCESS
{
	ULONG_PTR ulptrProcessId;
	LIST_ENTRY ActiveProcessList;
	/*
		Add-Context
	*/
}ACTIVE_PROCESS, *PACTIVE_PROCESS;

#ifdef __cplusplus
extern "C" {
#endif

	void
	MFDInsertActiveProcess(
		_In_ PACTIVE_PROCESS pActiveProcess
	);
	
	PACTIVE_PROCESS
	MFDDeleteActiveProcess(
		_In_ ULONG_PTR ulptrProcessId
	);

	void
	MFDDeleteAllProcess(void);

	void
	MFDProcessNotifyRoutine(
		_In_ HANDLE hParentId,
		_In_ HANDLE hProcessId,
		_In_ BOOLEAN bCreate
	);

	NTSTATUS
	MFDSetProcessNotifyRoutine(
		_In_ PVOID pvProcessNotifyRoutine
	);

	NTSTATUS
	MFDRemoveProcessNotifyRoutine(
		_In_ PVOID pvProcessNotifyRoutine
	);

#ifdef __cplusplus
}
#endif

#endif