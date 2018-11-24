#pragma once
#ifdef _KERNEL_MODE
#include <ntifs.h>
#include "mfd_undocument.h"

typedef struct _HANDLE_TABLE_7
{
	ULONG_PTR TableCode;
	PEPROCESS *QuotaProcess;
	HANDLE UniqueProcessId;
	PVOID HandleLock;
	LIST_ENTRY HandleTableList;
	EX_PUSH_LOCK HandleContentionEvent;
	PVOID DebugInfo;
	INT ExtraInfoPages;
	ULONG Flags;
	ULONG FirstFreeHandle;
	PVOID LastFreeHandleEntry;
	ULONG HandleCount;
	ULONG NextHandleNeedingPool;
}HANDLE_TABLE_7, *PHANDLE_TABLE_7;

#endif