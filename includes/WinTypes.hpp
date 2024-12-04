#pragma once

namespace WinTypes
{
    typedef struct _PEB_LDR_DATA
    {
        ULONG Length;
        UCHAR Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID EntryInProgress;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

    typedef struct _UNICODE_STRING
    {
        WORD Length;
        WORD MaximumLength;
        WORD* Buffer;
    } UNICODE_STRING, * PUNICODE_STRING;

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
    } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

    typedef struct _PEB {
        BYTE                          Reserved1[2];
        BYTE                          BeingDebugged;
        BYTE                          Reserved2[1];
        PVOID                         Reserved3[2];
        PPEB_LDR_DATA                 Ldr;
    }PEB, * PPEB;

    typedef struct _TEB {
        PVOID Reserved1[12];
        PPEB  ProcessEnvironmentBlock;
        PVOID Reserved2[399];
        BYTE  Reserved3[1952];
        PVOID TlsSlots[64];
        BYTE  Reserved4[8];
        PVOID Reserved5[26];
        PVOID ReservedForOle;
        PVOID Reserved6[4];
        PVOID TlsExpansionSlots;
    } TEB, * PTEB;

    typedef struct _SYSTEM_BASIC_INFORMATION {
        ULONG Reserved;
        ULONG TimerResolution;
        ULONG PageSize;
        ULONG NumberOfPhysicalPages;
        ULONG LowestPhysicalPageNumber;
        ULONG HighestPhysicalPageNumber;
        ULONG AllocationGranularity;
        ULONG_PTR MinimumUserModeAddress;
        ULONG_PTR MaximumUserModeAddress;
        KAFFINITY ActiveProcessorsAffinityMask;
        CHAR NumberOfProcessors;
    }SYSTEM_BASIC_INFORMATION, PSYSTEM_BASIC_INFORMATION;

    typedef enum _MEMORY_INFORMATION_CLASS {
        MemoryBasicInformation
    } MEMORY_INFORMATION_CLASS;

    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
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
        SystemNextEventIdInformation,
        SystemEventIdsInformation,
        SystemCrashDumpInformation,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeperation,
        SystemPlugPlayBusInformation,
        SystemDockInformation,
        SystemPowerInformation,
        SystemProcessorSpeedInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation
    } SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

    typedef struct _CLIENT_ID
    {
        std::uintptr_t UniqueProcess;
        std::uintptr_t UniqueThread;
    } CLIENT_ID, * PCLIENT_ID;

    typedef enum class _KWAIT_REASON
    {
        Executive = 0,
        FreePage = 1,
        PageIn = 2,
        PoolAllocation = 3,
        DelayExecution = 4,
        Suspended = 5,
        UserRequest = 6,
        WrExecutive = 7,
        WrFreePage = 8,
        WrPageIn = 9,
        WrPoolAllocation = 10,
        WrDelayExecution = 11,
        WrSuspended = 12,
        WrUserRequest = 13,
        WrEventPair = 14,
        WrQueue = 15,
        WrLpcReceive = 16,
        WrLpcReply = 17,
        WrVirtualMemory = 18,
        WrPageOut = 19,
        WrRendezvous = 20,
        Spare2 = 21,
        Spare3 = 22,
        Spare4 = 23,
        Spare5 = 24,
        WrCalloutStack = 25,
        WrKernel = 26,
        WrResource = 27,
        WrPushLock = 28,
        WrMutex = 29,
        WrQuantumEnd = 30,
        WrDispatchInt = 31,
        WrPreempted = 32,
        WrYieldExecution = 33,
        WrFastMutex = 34,
        WrGuardedMutex = 35,
        WrRundown = 36,
        MaximumWaitReason = 37
    } KWAIT_REASON;

    typedef struct _SYSTEM_THREAD {
        LARGE_INTEGER           KernelTime;
        LARGE_INTEGER           UserTime;
        LARGE_INTEGER           CreateTime;
        ULONG                   WaitTime;
        PVOID                   StartAddress;
        CLIENT_ID               ClientId;
        LONG					Priority;
        LONG                    BasePriority;
        ULONG                   ContextSwitchCount;
        ULONG                   State;
        KWAIT_REASON            WaitReason;
    } SYSTEM_THREAD, * PSYSTEM_THREAD;

    typedef struct _SYSTEM_PROCESS_INFORMATION
    {
        ULONG			NextEntryOffset;
        ULONG			NumberOfThreads;
        LARGE_INTEGER	WorkingSetPrivateSize;
        ULONG			HardFaultCount;
        ULONG			NumberOfThreadsHighWatermark;
        ULONGLONG		CycleTime;
        LARGE_INTEGER	CreateTime;
        LARGE_INTEGER	UserTime;
        LARGE_INTEGER	KernelTime;
        UNICODE_STRING	ImageName;
        LONG			BasePriority;
        HANDLE			UniqueProcessId;
        HANDLE			InheritedFromUniqueProcessId;
        ULONG			HandleCount;
        ULONG			SessionId;
        ULONG_PTR		UniqueProcessKey;
        SIZE_T			PeakVirtualSize;
        SIZE_T			VirtualSize;
        ULONG			PageFaultCount;
        SIZE_T 			PeakWorkingSetSize;
        SIZE_T			WorkingSetSize;
        SIZE_T			QuotaPeakPagedPoolUsage;
        SIZE_T 			QuotaPagedPoolUsage;
        SIZE_T 			QuotaPeakNonPagedPoolUsage;
        SIZE_T 			QuotaNonPagedPoolUsage;
        SIZE_T 			PagefileUsage;
        SIZE_T 			PeakPagefileUsage;
        SIZE_T 			PrivatePageCount;
        LARGE_INTEGER	ReadOperationCount;
        LARGE_INTEGER	WriteOperationCount;
        LARGE_INTEGER	OtherOperationCount;
        LARGE_INTEGER 	ReadTransferCount;
        LARGE_INTEGER	WriteTransferCount;
        LARGE_INTEGER	OtherTransferCount;
        SYSTEM_THREAD	Threads[1];
    } SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

    typedef struct _OBJECT_ATTRIBUTES {
        ULONG           Length;
        HANDLE          RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG           Attributes;
        PVOID           SecurityDescriptor;
        PVOID           SecurityQualityOfService;
    } OBJECT_ATTRIBUTES;
}