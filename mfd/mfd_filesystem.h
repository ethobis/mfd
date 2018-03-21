#ifndef __MFD_FILESYSTEM_H__
#define __MFD_FILESYSTEM_H__

#pragma warning(push)
#pragma warning(disable:4510)
#pragma warning(disable:4512)
#pragma warning(disable:4610)
#include <fltKernel.h>
#pragma warning(pop)
#pragma optimize("", off)


#ifdef __cplusplus
extern "C" {
#endif

	ULONG
	GetVolumeDeviceCharacteristics(
		_In_ PCFLT_RELATED_OBJECTS pFltObjects
	);

	BOOLEAN
	GetVolumeDeviceName(
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Out_ PWCHAR pwchOutVolumeDeviceName
	);

	BOOLEAN
	GetFilePath(
		_In_ PFLT_CALLBACK_DATA pData,
		_In_ PCFLT_RELATED_OBJECTS pFltObjects,
		_Out_ PWCHAR* pwchOutFilePath,
		_In_ BOOLEAN bWithVolumeDosName
	);

	void
	GetEnumerateVolume(
		_In_ PFLT_FILTER pFltFilter
	);

#ifdef __cplusplus
}
#endif

#endif