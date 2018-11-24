#pragma once
#ifdef _KERNEL_MODE
#include <ntifs.h>
#include "mfd_undocument.h"

typedef struct _HANDLE_TABLE_8
{
	ULONG NextHandleNeedingPool;
	LONG ExtraInfoPages;
	ULONG_PTR TableCode;
	PEPROCESS QuotaProcess;
	LIST_ENTRY HandleTableList;
	ULONG UniqueProcessId;
	ULONG Flags;
	EX_PUSH_LOCK HandleContentionEvent;
	EX_PUSH_LOCK HandleTableLock;
}HANDLE_TABLE_8, *PHANDLE_TABLE_8;

#endif