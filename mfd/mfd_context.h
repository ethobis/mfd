#pragma once
#define RTL_USE_AVL_TABLES 0
#include <fltKernel.h>

#include "mfd_cache.h"

typedef enum _FILTER_BEHAVIOR_TYPE
{
	FilterBehaviorDeafult,
	FilterBehaviorOpen,
	FilterBehaviorCreate,
	FilterBehaviorWrite,
	FilterBehaviorOverwrite,
	FilterBehaviorRename,
	FilterBehaviorDelete
}FILTER_BEHAVIOR_TYPE;

typedef struct _FILTER_SCAN_CONTEXT
{
	LONG ReferenceCount;
	PFLT_INSTANCE pFilterInstance;
	PFILE_OBJECT pFileObject;
	HANDLE hSectionHandle;
	PVOID pvSectionObject;
	LONGLONG FileSize;
	KEVENT ScanCompleteNotification;
	LIST_ENTRY ScanList;
	LONGLONG ScanId;
	ULONG ScanThreadId;
	UCHAR IRPMajorFunction;
	BOOLEAN bIoWaitOnScanCompleteNotificationAborted;
}FILTER_SCAN_CONTEXT, *PFILTER_SCAN_CONTEXT;

typedef struct _FILTER_CONTEXT
{
	PFLT_FILTER pFilter;
	PFLT_PORT pScanServerPort;
	PFLT_PORT pScanClientPort;
	PFLT_PORT pAbortServerPort;
	PFLT_PORT pAbortClientPort;
	PFLT_PORT pQueryServerPort;
	PFLT_PORT pQueryClientPort;
	LONGLONG ScanCounter;
	LIST_ENTRY ScanListHead;
	ERESOURCE ScanListLock;
	BOOLEAN bUnloading;
}FILTER_CONTEXT, *PFILTER_CONTEXT;
#define FILTER_CONNECTION_TAG 'cdfm'

typedef struct _FILTER_INSTANCE_CONTEXT
{
	PFLT_VOLUME pVolume;
	PFLT_INSTANCE pInstance;
	FLT_FILESYSTEM_TYPE VolumeFileSystemType;
	RTL_GENERIC_TABLE FileStateCacheTable;
	ERESOURCE InstanceLock;
}FILTER_INSTANCE_CONTEXT, *PFILTER_INSTANCE_CONTEXT;
#define FILTER_INSTANCE_CONTEXT_SIZE sizeof(FILTER_INSTANCE_CONTEXT)
#define FILTER_INSTANCE_CONTEXT_TAG 'idfm'

typedef struct _FILTER_STREAM_CONTEXT
{
	ULONG Flags;
	FILTER_FILE_REFERENCE FileId;
	PKEVENT ScanSyncEvent;
	LONG State;
}FILTER_STREAM_CONTEXT, *PFILTER_STREAM_CONTEXT;
#define FILTER_STREAM_CONTEXT_SIZE sizeof(FILTER_STREAM_CONTEXT)
#define FILTER_STREAM_CONTEXT_TAG 'rdfm'

#define FILTER_FLAG_PREFETCH 0x00000001

typedef struct _FILTER_STREAMHANDLE_CONTEXT
{
	ULONG Flags;
}FILTER_STREAMHANDLE_CONTEXT, *PFILTER_STREAMHANDLE_CONTEXT;
#define FILTER_STREAMHANDLE_CONTEXT_SIZE sizeof(FILTER_STREAMHANDLE_CONTEXT)
#define FILTER_STREAMHANDLE_CONTEXT_TAG 'rdfm'