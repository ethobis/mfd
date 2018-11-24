#pragma once
#ifdef _KERNEL_MODE
#include <ntddk.h>
#pragma warning(disable:4201)
#pragma warning(disable:4311)

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifdef __cplusplus
extern "C" {
#endif

	//
	// PROCESS INFORMATION
	//

	NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationProcess(
		_In_ HANDLE ProcessHandle,
		_In_ PROCESSINFOCLASS ProcessInformationClass,
		_Out_ PVOID ProcessInformation,
		_In_ ULONG ProcessInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

	//
	// SYSTEM INFORMATION
	//

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation,
		SystemProcessorInformation,
		SystemPerformanceInformation,
		SystemTimeOfDayInformation,
		SystemPathInformation, /// Obsolete: Use KUSER_SHARED_DATA
		SystemProcessInformation,
		SystemCallCountInformation,
		SystemDeviceInformation,
		SystemProcessorPerformanceInformation,
		SystemFlagsInformation,
		SystemCallTimeInformation,
		SystemModuleInformation,
		SystemLocksInformation,
		SystemStackTraceInformation,
		SystemPagedPoolInformation,
		SystemNonPagedPoolInformation,
		SystemHandleInformation,
		SystemObjectInformation,
		SystemPageFileInformation,
		SystemVdmInstemulInformation,
		SystemVdmBopInformation,
		SystemFileCacheInformation,
		SystemPoolTagInformation,
		SystemInterruptInformation,
		SystemDpcBehaviorInformation,
		SystemFullMemoryInformation,
		SystemLoadGdiDriverInformation,
		SystemUnloadGdiDriverInformation,
		SystemTimeAdjustmentInformation,
		SystemSummaryMemoryInformation,
		SystemMirrorMemoryInformation,
		SystemPerformanceTraceInformation,
		SystemObsolete0,
		SystemExceptionInformation,
		SystemCrashDumpStateInformation,
		SystemKernelDebuggerInformation,
		SystemContextSwitchInformation,
		SystemRegistryQuotaInformation,
		SystemExtendServiceTableInformation,  // used to be SystemLoadAndCallImage
		SystemPrioritySeperation,
		SystemPlugPlayBusInformation,
		SystemDockInformation,
		SystemPowerInformationNative,
		SystemProcessorSpeedInformation,
		SystemCurrentTimeZoneInformation,
		SystemLookasideInformation,
		SystemTimeSlipNotification,
		SystemSessionCreate,
		SystemSessionDetach,
		SystemSessionInformation,
		SystemRangeStartInformation,
		SystemVerifierInformation,
		SystemAddVerifier,
		SystemSessionProcessesInformation,
		SystemLoadGdiDriverInSystemSpaceInformation,
		SystemNumaProcessorMap,
		SystemPrefetcherInformation,
		SystemExtendedProcessInformation,
		SystemRecommendedSharedDataAlignment,
		SystemComPlusPackage,
		SystemNumaAvailableMemory,
		SystemProcessorPowerInformation,
		SystemEmulationBasicInformation,
		SystemEmulationProcessorInformation,
		SystemExtendedHanfleInformation,
		SystemLostDelayedWriteInformation,
		SystemBigPoolInformation,
		SystemSessionPoolTagInformation,
		SystemSessionMappedViewInformation,
		SystemHotpatchInformation,
		SystemObjectSecurityMode,
		SystemWatchDogTimerHandler,
		SystemWatchDogTimerInformation,
		SystemLogicalProcessorInformation,
		SystemWo64SharedInformationObosolete,
		SystemRegisterFirmwareTableInformationHandler,
		SystemFirmwareTableInformation,
		SystemModuleInformationEx,
		SystemVerifierTriageInformation,
		SystemSuperfetchInformation,
		SystemMemoryListInformation,
		SystemFileCacheInformationEx,
		SystemThreadPriorityClientIdInformation,
		SystemProcessorIdleCycleTimeInformation,
		SystemVerifierCancellationInformation,
		SystemProcessorPowerInformationEx,
		SystemRefTraceInformation,
		SystemSpecialPoolInformation,
		SystemProcessIdInformation,
		SystemErrorPortInformation,
		SystemBootEnvironmentInformation,
		SystemHypervisorInformation,
		SystemVerifierInformationEx,
		SystemTimeZoneInformation,
		SystemImageFileExecutionOptionsInformation,
		SystemCoverageInformation,
		SystemPrefetchPathInformation,
		SystemVerifierFaultsInformation,
		MaxSystemInfoClass,
	}SYSTEM_INFORMATION_CLASS;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION {
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		CHAR FullPathName[256];
	}RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES {
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	}RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

	typedef struct _SYSTEM_THREAD_INFORMATION {
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG WaitTime;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		LONG BasePriority;
		ULONG ContextSwitchCount;
		ULONG State;
		KWAIT_REASON WaitReason;
	}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER Reserved[3];
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG Reserved2[2];
		ULONG PrivatePageCount;
		VM_COUNTERS VirtualMemoryCounters;
		IO_COUNTERS IoCounters;
		SYSTEM_THREAD_INFORMATION Threads[1];
	}SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

	NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_Inout_ PVOID SystemInformation,
		_In_ ULONG SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

	//
	// LDR MODULES
	//

	typedef BOOLEAN(NTAPI *PLDR_INIT_ROUTINE)(
		_In_ PVOID DllHandle,
		_In_ ULONG Reason,
		_In_opt_ PVOID Context
		);

	typedef struct _LDR_SERVICE_TAG_RECORD
	{
		struct _LDR_SERVICE_TAG_RECORD *Next;
		ULONG ServiceTag;
	}LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

	typedef struct _LDRP_CSLIST
	{
		PSINGLE_LIST_ENTRY Tail;
	}LDRP_CSLIST, *PLDRP_CSLIST;

	typedef enum _LDR_DDAG_STATE
	{
		LdrModulesMerged = -5,
		LdrModulesInitError = -4,
		LdrModulesSnapError = -3,
		LdrModulesUnloaded = -2,
		LdrModulesUnloading = -1,
		LdrModulesPlaceHolder = 0,
		LdrModulesMapping = 1,
		LdrModulesMapped = 2,
		LdrModulesWaitingForDependencies = 3,
		LdrModulesSnapping = 4,
		LdrModulesSnapped = 5,
		LdrModulesCondensed = 6,
		LdrModulesReadyToInit = 7,
		LdrModulesInitializing = 8,
		LdrModulesReadyToRun = 9
	}LDR_DDAG_STATE;

	typedef struct _LDR_DDAG_NODE
	{
		LIST_ENTRY Modules;
		PLDR_SERVICE_TAG_RECORD ServiceTagList;
		ULONG LoadCount;
		ULONG LoadWhileUnloadingCount;
		ULONG LowestLink;
		union
		{
			LDRP_CSLIST Dependencies;
			SINGLE_LIST_ENTRY RemovalLink;
		};
		LDRP_CSLIST IncomingDependencies;
		LDR_DDAG_STATE State;
		SINGLE_LIST_ENTRY CondenseLink;
		ULONG PreorderNumber;
	}LDR_DDAG_NODE, *PLDR_DDAG_NODE;

	typedef enum _LDR_DLL_LOAD_REASON
	{
		LoadReasonStaticDependency,
		LoadReasonStaticForwarderDependency,
		LoadReasonDynamicForwarderDependency,
		LoadReasonDelayloadDependency,
		LoadReasonDynamicLoad,
		LoadReasonAsImageLoad,
		LoadReasonAsDataLoad,
		LoadReasonEnclavePrimary,
		LoadReasonEnclaveDependency,
		LoadReasonUnknown = -1
	} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PLDR_INIT_ROUTINE EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		union
		{
			UCHAR FlagGroup[4];
			ULONG Flags;
			struct
			{
				ULONG PackagedBinary : 1;
				ULONG MarkedForRemoval : 1;
				ULONG ImageDll : 1;
				ULONG LoadNotificationsSent : 1;
				ULONG TelemetryEntryProcessed : 1;
				ULONG ProcessStaticImport : 1;
				ULONG InLegacyLists : 1;
				ULONG InIndexes : 1;
				ULONG ShimDll : 1;
				ULONG InExceptionTable : 1;
				ULONG ReservedFlags1 : 2;
				ULONG LoadInProgress : 1;
				ULONG LoadConfigProcessed : 1;
				ULONG EntryProcessed : 1;
				ULONG ProtectDelayLoad : 1;
				ULONG ReservedFlags3 : 2;
				ULONG DontCallForThreads : 1;
				ULONG ProcessAttachCalled : 1;
				ULONG ProcessAttachFailed : 1;
				ULONG CorDeferredValidate : 1;
				ULONG CorImage : 1;
				ULONG DontRelocate : 1;
				ULONG CorILOnly : 1;
				ULONG ReservedFlags5 : 3;
				ULONG Redirected : 1;
				ULONG ReservedFlags6 : 2;
				ULONG CompatDatabaseProcessed : 1;
			};
		};
		USHORT ObsoleteLoadCount;
		USHORT TlsIndex;
		LIST_ENTRY HashLinks;
		ULONG TimeDateStamp;
		struct _ACTIVATION_CONTEXT *EntryPointActivationContext;
		PVOID Lock;
		PLDR_DDAG_NODE DdagNode;
		LIST_ENTRY NodeModuleLink;
		struct _LDRP_LOAD_CONTEXT *LoadContext;
		PVOID ParentDllBase;
		PVOID SwitchBackContext;
		RTL_BALANCED_NODE BaseAddressIndexNode;
		RTL_BALANCED_NODE MappingInfoIndexNode;
		ULONG_PTR OriginalBase;
		LARGE_INTEGER LoadTime;
		ULONG BaseNameHashValue;
		LDR_DLL_LOAD_REASON LoadReason;
		ULONG ImplicitPathOptions;
		ULONG ReferenceCount;
		ULONG DependentLoadFlags;
		UCHAR SigningLevel;
	}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	//
	// TEB
	//

	typedef BOOLEAN (NTAPI *PLDR_INIT_ROUTINE)(
		_In_ PVOID DllHandle,
		_In_ ULONG Reason,
		_In_opt_ PVOID Context
		);

	typedef struct _ACTIVATION_CONTEXT_STACK
	{
		struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
		LIST_ENTRY FrameListCache;
		ULONG Flags;
		ULONG NextCookieSequenceNumber;
		ULONG StackId;
	}ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

	#define GDI_BATCH_BUFFER_SIZE 310

	typedef struct _GDI_TEB_BATCH
	{
		ULONG Offset;
		ULONG_PTR HDC;
		ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
	}GDI_TEB_BATCH, *PGDI_TEB_BATCH;

	typedef struct _TEB_ACTIVE_FRAME_CONTEXT
	{
		ULONG Flags;
		PSTR FrameName;
	}TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

	typedef struct _TEB_ACTIVE_FRAME
	{
		ULONG Flags;
		struct _TEB_ACTIVE_FRAME *Previous;
		PTEB_ACTIVE_FRAME_CONTEXT Context;
	}TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

	typedef struct _TEB
	{
		NT_TIB NtTib;

		PVOID EnvironmentPointer;
		CLIENT_ID ClientId;
		PVOID ActiveRpcHandle;
		PVOID ThreadLocalStoragePointer;
		PPEB ProcessEnvironmentBlock;

		ULONG LastErrorValue;
		ULONG CountOfOwnedCriticalSections;
		PVOID CsrClientThread;
		PVOID Win32ThreadInfo;
		ULONG User32Reserved[26];
		ULONG UserReserved[5];
		PVOID WOW32Reserved;
		LCID CurrentLocale;
		ULONG FpSoftwareStatusRegister;
		PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
		PVOID SystemReserved1[30];
#else
		PVOID SystemReserved1[26];
#endif

		CHAR PlaceholderCompatibilityMode;
		CHAR PlaceholderReserved[11];
		ULONG ProxiedProcessId;
		ACTIVATION_CONTEXT_STACK ActivationStack;

		UCHAR WorkingOnBehalfTicket[8];
		NTSTATUS ExceptionCode;

		PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
		ULONG_PTR InstrumentationCallbackSp;
		ULONG_PTR InstrumentationCallbackPreviousPc;
		ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
		ULONG TxFsContext;
#endif

		BOOLEAN InstrumentationCallbackDisabled;
#ifndef _WIN64
		UCHAR SpareBytes[23];
		ULONG TxFsContext;
#endif
		GDI_TEB_BATCH GdiTebBatch;
		CLIENT_ID RealClientId;
		HANDLE GdiCachedProcessHandle;
		ULONG GdiClientPID;
		ULONG GdiClientTID;
		PVOID GdiThreadLocalInfo;
		ULONG_PTR Win32ClientInfo[62];
		PVOID glDispatchTable[233];
		ULONG_PTR glReserved1[29];
		PVOID glReserved2;
		PVOID glSectionInfo;
		PVOID glSection;
		PVOID glTable;
		PVOID glCurrentRC;
		PVOID glContext;

		NTSTATUS LastStatusValue;
		UNICODE_STRING StaticUnicodeString;
		WCHAR StaticUnicodeBuffer[261];

		PVOID DeallocationStack;
		PVOID TlsSlots[64];
		LIST_ENTRY TlsLinks;

		PVOID Vdm;
		PVOID ReservedForNtRpc;
		PVOID DbgSsReserved[2];

		ULONG HardErrorMode;
#ifdef _WIN64
		PVOID Instrumentation[11];
#else
		PVOID Instrumentation[9];
#endif
		GUID ActivityId;

		PVOID SubProcessTag;
		PVOID PerflibData;
		PVOID EtwTraceData;
		PVOID WinSockData;
		ULONG GdiBatchCount;

		union
		{
			PROCESSOR_NUMBER CurrentIdealProcessor;
			ULONG IdealProcessorValue;
			struct
			{
				UCHAR ReservedPad0;
				UCHAR ReservedPad1;
				UCHAR ReservedPad2;
				UCHAR IdealProcessor;
			};
		};

		ULONG GuaranteedStackBytes;
		PVOID ReservedForPerf;
		PVOID ReservedForOle;
		ULONG WaitingOnLoaderLock;
		PVOID SavedPriorityState;
		ULONG_PTR ReservedForCodeCoverage;
		PVOID ThreadPoolData;
		PVOID *TlsExpansionSlots;
#ifdef _WIN64
		PVOID DeallocationBStore;
		PVOID BStoreLimit;
#endif
		ULONG MuiGeneration;
		ULONG IsImpersonating;
		PVOID NlsCache;
		PVOID pShimData;
		USHORT HeapVirtualAffinity;
		USHORT LowFragHeapDataSlot;
		HANDLE CurrentTransactionHandle;
		PTEB_ACTIVE_FRAME ActiveFrame;
		PVOID FlsData;

		PVOID PreferredLanguages;
		PVOID UserPrefLanguages;
		PVOID MergedPrefLanguages;
		ULONG MuiImpersonation;

		union
		{
			USHORT CrossTebFlags;
			USHORT SpareCrossTebBits : 16;
		};
		union
		{
			USHORT SameTebFlags;
			struct
			{
				USHORT SafeThunkCall : 1;
				USHORT InDebugPrint : 1;
				USHORT HasFiberData : 1;
				USHORT SkipThreadAttach : 1;
				USHORT WerInShipAssertCode : 1;
				USHORT RanProcessInit : 1;
				USHORT ClonedThread : 1;
				USHORT SuppressDebugMsg : 1;
				USHORT DisableUserStackWalk : 1;
				USHORT RtlExceptionAttached : 1;
				USHORT InitialThread : 1;
				USHORT SessionAware : 1;
				USHORT LoadOwner : 1;
				USHORT LoaderWorker : 1;
				USHORT SkipLoaderInit : 1;
				USHORT SpareSameTebBits : 1;
			};
		};

		PVOID TxnScopeEnterCallback;
		PVOID TxnScopeExitCallback;
		PVOID TxnScopeContext;
		ULONG LockCount;
		LONG WowTebOffset;
		PVOID ResourceRetValue;
		PVOID ReservedForWdf;
		ULONGLONG ReservedForCrt;
		GUID EffectiveContainerId;
	}TEB, *PTEB;

	NTKERNELAPI PTEB NTAPI PsGetThreadTeb(
		_In_ PETHREAD pEthread
	);

	//
	// PEB
	//

	typedef struct _PEB_LDR_DATA
	{
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	}PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS32 {
		UCHAR Reserved1[16];
		ULONG Reserved2[10];
		UNICODE_STRING32 ImagePathName;
		UNICODE_STRING32 CommandLine;
	} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

	typedef struct _PEB32 {
		UCHAR Reserved1[2];
		UCHAR BeingDebugged;
		UCHAR Reserved2[1];
		ULONG Reserved3[2];
		ULONG LoaderData;				// PEB_LDR_DATA
		ULONG ProcessParameters;		// PRTL_USER_PROCESS_PARAMETERS32
		UCHAR Reserved4[104];
		ULONG Reserved5[52];
		ULONG PostProcessInitRoutine;
		UCHAR Reserved6[128];
		ULONG Reserved7[1];
		ULONG SessionId;
	}PEB32, *PPEB32;

	typedef struct _RTL_USER_PROCESS_PARAMETERS64 {
		UCHAR Reserved1[16];
		ULONGLONG Reserved2[10];
		UNICODE_STRING64 ImagePathName;
		UNICODE_STRING64 CommandLine;
	} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

	typedef struct _PEB64 {
		UCHAR Reserved1[2];
		UCHAR BeingDebugged;
		UCHAR Reserved2[21];
		ULONGLONG LoaderData;				// PEB_LDR_DATA
		ULONGLONG ProcessParameters;		// PRTL_USER_PROCESS_PARAMETERS64
		UCHAR Reserved3[520];
		ULONGLONG PostProcessInitRoutine;
		UCHAR Reserved4[136];
		ULONG SessionId;
	}PEB64, *PPEB64;

#ifdef _M_IX86
#define PEB PEB32
#define PPEB PPEB32
#elif _M_X64
#define PEB PEB64
#define PPEB PPEB64
#endif

	NTKERNELAPI PPEB NTAPI PsGetProcessPeb(
		_In_ PEPROCESS pEprocess
	);

	//
	// KERNEL OBJECT
	//

	typedef struct _OBJECT_HEADER
	{
		ULONG_PTR PointerCount;
		union
		{
			ULONG_PTR HandleCount;
			PVOID NextToFree;
		};
		PVOID Lock;
		UCHAR TypeIndex;
		union
		{
			UCHAR TraceFlags;
			struct
			{
				UCHAR DbgRefTrace : 1;
				UCHAR DbgTracePermanent : 1;
			};
		};
		UCHAR InfoMask;
		union
		{
			UCHAR Flags;
			struct
			{
				UCHAR NewObject : 1;
				UCHAR KernelObject : 1;
				UCHAR KernelOnlyAccess : 1;
				UCHAR ExclusiveObject : 1;
				UCHAR PermanentObject : 1;
				UCHAR DefaultSecurityQuota : 1;
				UCHAR SingleHandleEntry : 1;
				UCHAR DeletedInline : 1;
			};
		};
		ULONG Spare;
		union
		{
			struct _OBJECT_CREATE_INFORMATION * ObjectCreateInfo;
			PVOID QuotaBlockCharged;
		};
		PVOID SecurityDescriptor;
		struct _QUAD Body;
	} OBJECT_HEADER, *POBJECT_HEADER;

	//
	// APC
	//

	typedef enum _KAPC_ENVIRONMENT
	{
		OriginalApcEnvironment,
		AttachedApcEnvironment,
		CurrentApcEnvironment,
		InsertApcEnvironment
	} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

	typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
		_In_ PVOID NormalContext,
		_In_ PVOID SystemArgument1,
		_In_ PVOID SystemArgument2
	);

	typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
		_In_ PRKAPC Apc,
		_Inout_ PKNORMAL_ROUTINE *NormalRoutine,
		_Inout_ PVOID *NormalContext,
		_Inout_ PVOID *SystemArgument1,
		_Inout_ PVOID *SystemArgument2
	);

	typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(
		_In_ PRKAPC Apc
	);

	NTKERNELAPI	VOID NTAPI KeInitializeApc(
		_Out_ PKAPC Apc,
		_In_ PKTHREAD Thread,
		_In_ KAPC_ENVIRONMENT ApcStateIndex,
		_In_ PKKERNEL_ROUTINE KernelRoutine,
		_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
		_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
		_In_opt_ KPROCESSOR_MODE ApcMode,
		_In_opt_ PVOID NormalContext
	);

	NTKERNELAPI	BOOLEAN	NTAPI KeInsertQueueApc(
		_Inout_ PKAPC Apc,
		_In_opt_ PVOID SystemArgument1,
		_In_opt_ PVOID SystemArgument2,
		_In_ KPRIORITY Increment
	);

	//
	// PE IMAGE
	//

	typedef struct _IMAGE_DOS_HEADER 
	{
		USHORT e_magic;
		USHORT e_cblp;
		USHORT e_cp;
		USHORT e_crlc;
		USHORT e_cparhdr;
		USHORT e_minalloc;
		USHORT e_maxalloc;
		USHORT e_ss;
		USHORT e_sp;
		USHORT e_csum;
		USHORT e_ip;
		USHORT e_cs;
		USHORT e_lfarlc;
		USHORT e_ovno;
		USHORT e_res[4];
		USHORT e_oemid;
		USHORT e_oeminfo;
		USHORT e_res2[10];
		LONG e_lfanew;
	}IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

	typedef struct _IMAGE_FILE_HEADER 
	{
		USHORT Machine;
		USHORT NumberOfSections;
		ULONG TimeDateStamp;
		ULONG PointerToSymbolTable;
		ULONG NumberOfSymbols;
		USHORT SizeOfOptionalHeader;
		USHORT Characteristics;
	}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER 20

#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
#define IMAGE_FILE_AGGRESIVE_WS_TRIM 0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080
#define IMAGE_FILE_32BIT_MACHINE 0x0100
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800
#define IMAGE_FILE_SYSTEM 0x1000
#define IMAGE_FILE_DLL 0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000

#define IMAGE_FILE_MACHINE_UNKNOWN 0
#define IMAGE_FILE_MACHINE_I386 0x014c
#define IMAGE_FILE_MACHINE_R3000 0x0162
#define IMAGE_FILE_MACHINE_R4000 0x0166
#define IMAGE_FILE_MACHINE_R10000 0x0168
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x0169
#define IMAGE_FILE_MACHINE_ALPHA 0x0184
#define IMAGE_FILE_MACHINE_SH3 0x01a2
#define IMAGE_FILE_MACHINE_SH3DSP 0x01a3
#define IMAGE_FILE_MACHINE_SH3E 0x01a4
#define IMAGE_FILE_MACHINE_SH4 0x01a6
#define IMAGE_FILE_MACHINE_SH5 0x01a8
#define IMAGE_FILE_MACHINE_ARM 0x01c0
#define IMAGE_FILE_MACHINE_THUMB 0x01c2
#define IMAGE_FILE_MACHINE_AM33 0x01d3
#define IMAGE_FILE_MACHINE_POWERPC 0x01F0
#define IMAGE_FILE_MACHINE_POWERPCFP 0x01f1
#define IMAGE_FILE_MACHINE_IA64 0x0200
#define IMAGE_FILE_MACHINE_MIPS16 0x0266
#define IMAGE_FILE_MACHINE_ALPHA64 0x0284
#define IMAGE_FILE_MACHINE_MIPSFPU 0x036
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x0466
#define IMAGE_FILE_MACHINE_AXP64 IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE 0x0520
#define IMAGE_FILE_MACHINE_CEF 0x0CEF
#define IMAGE_FILE_MACHINE_EBC 0x0EBC
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_M32R 0x9041
#define IMAGE_FILE_MACHINE_CEE 0xC0EE

	typedef struct _IMAGE_DATA_DIRECTORY
	{
		ULONG VirtualAddress;
		ULONG Size;
	}IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

	typedef struct _IMAGE_OPTIONAL_HEADER 
	{
		USHORT Magic;
		UCHAR MajorLinkerVersion;
		UCHAR MinorLinkerVersion;
		ULONG SizeOfCode;
		ULONG SizeOfInitializedData;
		ULONG SizeOfUninitializedData;
		ULONG AddressOfEntryPoint;
		ULONG BaseOfCode;
		ULONG BaseOfData;
		ULONG ImageBase;
		ULONG SectionAlignment;
		ULONG FileAlignment;
		USHORT MajorOperatingSystemVersion;
		USHORT MinorOperatingSystemVersion;
		USHORT MajorImageVersion;
		USHORT MinorImageVersion;
		USHORT MajorSubsystemVersion;
		USHORT MinorSubsystemVersion;
		ULONG Win32VersionValue;
		ULONG SizeOfImage;
		ULONG SizeOfHeaders;
		ULONG CheckSum;
		USHORT Subsystem;
		USHORT DllCharacteristics;
		ULONG SizeOfStackReserve;
		ULONG SizeOfStackCommit;
		ULONG SizeOfHeapReserve;
		ULONG SizeOfHeapCommit;
		ULONG LoaderFlags;
		ULONG NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	}IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

	typedef struct _IMAGE_OPTIONAL_HEADER64
	{
		USHORT Magic;
		UCHAR MajorLinkerVersion;
		UCHAR MinorLinkerVersion;
		ULONG SizeOfCode;
		ULONG SizeOfInitializedData;
		ULONG SizeOfUninitializedData;
		ULONG AddressOfEntryPoint;
		ULONG BaseOfCode;
		ULONGLONG ImageBase;
		ULONG SectionAlignment;
		ULONG FileAlignment;
		USHORT MajorOperatingSystemVersion;
		USHORT MinorOperatingSystemVersion;
		USHORT MajorImageVersion;
		USHORT MinorImageVersion;
		USHORT MajorSubsystemVersion;
		USHORT MinorSubsystemVersion;
		ULONG Win32VersionValue;
		ULONG SizeOfImage;
		ULONG SizeOfHeaders;
		ULONG CheckSum;
		USHORT Subsystem;
		USHORT DllCharacteristics;
		ULONGLONG SizeOfStackReserve;
		ULONGLONG SizeOfStackCommit;
		ULONGLONG SizeOfHeapReserve;
		ULONGLONG SizeOfHeapCommit;
		ULONG LoaderFlags;
		ULONG NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	}IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

	typedef struct _IMAGE_NT_HEADERS64
	{
		ULONG Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	}IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

	typedef struct _IMAGE_NT_HEADERS
	{
		ULONG Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER32 OptionalHeader;
	}IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC 0x107

#ifdef _WIN64
	typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
	typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR64_MAGIC
	typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
	typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
#else
	typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
	typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR32_MAGIC
	typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
	typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
#endif

#define IMAGE_FIRST_SECTION(pNtHeaders)((PIMAGE_SECTION_HEADER) \
		((ULONG_PTR)(pNtHeaders) + \
		FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) + \
		((pNtHeaders))->FileHeader.SizeOfOptionalHeader))

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
	//#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT 7
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

#define IMAGE_SIZEOF_SHORT_NAME 8

	typedef struct _IMAGE_SECTION_HEADER
	{
		UCHAR Name[IMAGE_SIZEOF_SHORT_NAME];
		union
		{
			ULONG PhysicalAddress;
			ULONG VirtualSize;
		}Misc;
		ULONG VirtualAddress;
		ULONG SizeOfRawData;
		ULONG PointerToRawData;
		ULONG PointerToRelocations;
		ULONG PointerToLinenumbers;
		USHORT NumberOfRelocations;
		USHORT NumberOfLinenumbers;
		ULONG Characteristics;
	}IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER 40

#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080

#define IMAGE_SCN_LNK_OTHER 0x00000100
#define IMAGE_SCN_LNK_INFO 0x00000200
#define IMAGE_SCN_LNK_REMOVE 0x00000800
#define IMAGE_SCN_LNK_COMDAT 0x00001000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC 0x00004000
#define IMAGE_SCN_GPREL 0x00008000
#define IMAGE_SCN_MEM_FARDATA 0x00008000
#define IMAGE_SCN_MEM_PURGEABLE 0x00020000
#define IMAGE_SCN_MEM_16BIT 0x00020000
#define IMAGE_SCN_MEM_LOCKED 0x00040000
#define IMAGE_SCN_MEM_PRELOAD 0x00080000

#define IMAGE_SCN_ALIGN_1BYTES 0x00100000
#define IMAGE_SCN_ALIGN_2BYTES 0x00200000
#define IMAGE_SCN_ALIGN_4BYTES 0x00300000
#define IMAGE_SCN_ALIGN_8BYTES 0x00400000
#define IMAGE_SCN_ALIGN_16BYTES 0x00500000
#define IMAGE_SCN_ALIGN_32BYTES 0x00600000
#define IMAGE_SCN_ALIGN_64BYTES 0x00700000
#define IMAGE_SCN_ALIGN_128BYTES 0x00800000
#define IMAGE_SCN_ALIGN_256BYTES 0x00900000
#define IMAGE_SCN_ALIGN_512BYTES 0x00A00000
#define IMAGE_SCN_ALIGN_1024BYTES 0x00B00000
#define IMAGE_SCN_ALIGN_2048BYTES 0x00C00000
#define IMAGE_SCN_ALIGN_4096BYTES 0x00D00000
#define IMAGE_SCN_ALIGN_8192BYTES 0x00E00000

#define IMAGE_SCN_ALIGN_MASK 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED 0x08000000
#define IMAGE_SCN_MEM_SHARED 0x10000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

	typedef struct _IMAGE_BASE_RELOCATION
	{
		ULONG VirtualAddress;
		ULONG SizeOfBlock;
		//USHORT TypeOffset[1];
	}IMAGE_BASE_RELOCATION;
	typedef IMAGE_BASE_RELOCATION UNALIGNED *PIMAGE_BASE_RELOCATION;

#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGH 1
#define IMAGE_REL_BASED_LOW 2
#define IMAGE_REL_BASED_HIGHLOW 3
#define IMAGE_REL_BASED_HIGHADJ 4
#define IMAGE_REL_BASED_MIPS_JMPADDR 5
#define IMAGE_REL_BASED_MIPS_JMPADDR16 9
#define IMAGE_REL_BASED_IA64_IMM64 9
#define IMAGE_REL_BASED_DIR64 10

	typedef struct _IMAGE_IMPORT_BY_NAME
	{
		USHORT Hint;
		UCHAR Name[1];
	}IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

	typedef struct _IMAGE_IMPORT_DESCRIPTOR
	{
		union
		{
			ULONG Characteristics; 
			ULONG OriginalFirstThunk;
		} DUMMYUNIONNAME;
		ULONG TimeDateStamp;
		ULONG ForwarderChain;
		ULONG Name;
		ULONG FirstThunk;
	}IMAGE_IMPORT_DESCRIPTOR;
	typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

	typedef struct _IMAGE_EXPORT_DIRECTORY
	{
		ULONG Characteristics;
		ULONG TimeDateStamp;
		USHORT MajorVersion;
		USHORT MinorVersion;
		ULONG Name;
		ULONG Base;
		ULONG NumberOfFunctions;
		ULONG NumberOfNames;
		ULONG AddressOfFunctions;
		ULONG AddressOfNames;
		ULONG AddressOfNameOrdinals;
	}IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

	typedef struct _IMAGE_RESOURCE_DIRECTORY
	{
		ULONG Characteristics;
		ULONG TimeDateStamp;
		USHORT MajorVersion;
		USHORT MinorVersion;
		USHORT NumberOfNamedEntries;
		USHORT NumberOfIdEntries;
		//IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
	}IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

	typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY
	{
		union
		{
			struct
			{
				ULONG NameOffset : 31;
				ULONG NameIsString : 1;
			};
			ULONG Name;
			USHORT Id;
		};
		union
		{
			ULONG OffsetToData;
			struct
			{
				ULONG OffsetToDirectory : 31;
				ULONG DataIsDirectory : 1;
			};
		};
	}IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

#define DEF_RES_ID_INT 0
#define DEF_RES_ID_STRING 1
#define DEF_RES_TYPE_VERSION 0x10

#define DEF_DOS_HEADER_SIG 0x5A4D
#define DEF_NT_HEADER_SIG 0x4550

	typedef struct _IMAGE_RESOURCE_DATA_ENTRY
	{
		ULONG OffsetToData;
		ULONG Size;
		ULONG CodePage;
		ULONG Reserved;
	}IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

#ifndef IS_INTRESOURCE
#define IS_INTRESOURCE(_r) ((((ULONG_PTR)(_r)) >> 16) == 0)
#endif

	//
	// UNDOCUMENTED NT FUNCTION
	//

	typedef NTSTATUS(NTAPI* fpSeLocateProcessImageName)(
		_In_ PEPROCESS eprocess,
		_Out_ PUNICODE_STRING* puniProcessPath
	);

	typedef NTSTATUS(NTAPI* fpNtTerminateThread)(
		_In_ HANDLE ThreadHandle,
		_In_ NTSTATUS ExitStatus
	);

	typedef NTSTATUS(NTAPI* fpNtSuspendThread)(
		_In_ HANDLE ThreadHandle,
		_Out_ PULONG PreviousSuspendCount
	);

#ifdef __cplusplus
}
#endif
#endif