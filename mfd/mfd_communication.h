#pragma once
#include <fltKernel.h>

NTSTATUS MFDSendAbortToUser(
	_In_ ULONG ScanThreadId,
	_In_ LONGLONG ScanId
);