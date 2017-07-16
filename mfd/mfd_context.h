#ifndef __MFD_CONTEXT_H__
#define __MFD_CONTEXT_H__

#pragma warning(push)
#pragma warning(disable:4510)
#pragma warning(disable:4512)
#pragma warning(disable:4610)
#include <fltKernel.h>
#pragma warning(pop)
#pragma optimize("", off)

typedef struct _MFD_VOLUME_CONTEXT
{
	PVOID pvReserved;
}MFD_VOLUME_CONTEXT, *PMFD_VOLUME_CONTEXT;

typedef struct _PMFD_INSTANCE_CONTEXT
{
	PVOID pvReserved;
}MFD_INSTANCE_CONTEXT, *PMFD_INSTANCE_CONTEXT;

typedef struct _MFD_FILE_CONTEXT
{
	PVOID pvReserved;
}MFD_FILE_CONTEXT, *PMFD_FILE_CONTEXT;

typedef struct _MFD_STREAM_CONTEXT
{
	PVOID pvReserved;
}MFD_STREAM_CONTEXT, *PMFD_STREAM_CONTEXT;

typedef struct _MFD_STREAMHANDLE_CONTEXT
{
	PVOID pvReserved;
}MFD_STREAMHANDLE_CONTEXT, *PMFD_STREAMHANDLE_CONTEXT;

typedef struct _MFD_TRANSACTION_CONTEXT
{
	PVOID pvReserved;
}MFD_TRANSACTION_CONTEXT, *PMFD_TRANSACTION_CONTEXT;

#ifdef __cplusplus
extern "C" {
#endif



#ifdef __cplusplus
}
#endif

#endif