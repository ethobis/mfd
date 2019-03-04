#pragma once
#include <fltKernel.h>

EXTERN_C NTSTATUS MFDSendAbortToUser(
	_In_ ULONG ScanThreadId,
	_In_ LONGLONG ScanId
);