#ifndef __MFD_PROCESS_NOTIFY_H__
#define __MFD_PROCESS_NOTIFY_H__

#include <ntifs.h>
#include <ntddk.h>

typedef struct _ACTIVE_PROCESS_HEAD
{
	LIST_ENTRY ActiveProcessListHead;
	BOOLEAN bAcquired;
	ERESOURCE Resource;
	ULONG NumberOfActiveThread;
	NPAGED_LOOKASIDE_LIST ProcessNPLookasideList;
}ACTIVE_PROCESS_HEAD, *PACTIVE_PROCESS_HEAD;

typedef struct _ACTIVE_PROCESS
{
	PEPROCESS Process;
	LIST_ENTRY ActiveThreadList;
	/*
		Add-Context
	*/
}ACTIVE_PROCESS, *PACTIVE_PROCESS;

#ifdef __cplusplus
extern "C" {
#endif



#ifdef __cplusplus
}
#endif

#endif