#pragma once
#include <fltkernel.h>
#include <ntstrsafe.h>

PFLT_VOLUME_PROPERTIES MFDOpenVolumeProperties(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects
);

VOID MFDCloseVolumeProperties(
	_In_ PFLT_VOLUME_PROPERTIES pVolumeProperties
);

BOOLEAN MFDGetVolumeName(
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PUNICODE_STRING puniVolumeName
);

BOOLEAN MFDGetFilePath(
	_In_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Out_ PUNICODE_STRING puniOutFilePath
);