#pragma once
#include <fltkernel.h>
#include <ntstrsafe.h>

EXTERN_C PFLT_VOLUME_PROPERTIES MFDOpenVolumeProperties(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects
);

EXTERN_C VOID MFDCloseVolumeProperties(
	_In_ PFLT_VOLUME_PROPERTIES pVolumeProperties
);

EXTERN_C BOOLEAN MFDGetVolumeName(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PUNICODE_STRING puniVolumeName
);

EXTERN_C BOOLEAN MFDGetFilePath(
	_In_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PUNICODE_STRING puniOutFilePath
);