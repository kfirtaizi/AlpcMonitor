#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <Zydis/Zydis.h>

#pragma warning(disable:4152)

#define DEVICE_NAME L"\\Device\\AlpcMonitor"
#define SYMLINK_NAME L"\\DosDevices\\AlpcMonitor"

#define IOCTL_ALPC_START_MONITORING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALPC_STOP_MONITORING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALPC_GET_MESSAGE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALPC_SET_SSN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_STACK_FRAMES 32

#define MAX_JUMP_CODE_LENGTH 20
#define JUMP_TO_HOOK_SHELL_LENGTH 12
#define JUMP_TO_ORIGINAL_CODE_SHELL_LENGTH 14

// Message buffer structure for usermode
typedef struct _ALPC_MONITOR_MESSAGE {
    LARGE_INTEGER Timestamp;
    ULONG ProcessId;
    ULONG ThreadId;
    CHAR ProcessName[16];
    BOOLEAN IsSend;
    ULONG MessageId;
    USHORT MessageType;
    USHORT DataLength;
    USHORT TotalLength;
    UCHAR Data[2048];
    ULONG StackFrameCount;
    PVOID StackFrames[MAX_STACK_FRAMES];
} ALPC_MONITOR_MESSAGE, * PALPC_MONITOR_MESSAGE;

#define MESSAGE_BUFFER_SIZE 1000
typedef struct _MESSAGE_BUFFER {
    ALPC_MONITOR_MESSAGE Messages[MESSAGE_BUFFER_SIZE];
    ULONG WriteIndex;
    ULONG ReadIndex;
    KSPIN_LOCK Lock;
    KEVENT DataAvailableEvent;
    BOOLEAN MonitoringActive;
} MESSAGE_BUFFER, * PMESSAGE_BUFFER;

PDEVICE_OBJECT g_DeviceObject = NULL;
MESSAGE_BUFFER g_MessageBuffer = { 0 };

#define EPROCESS_IMAGEFILENAME_OFFSET 0x5a8

NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject);
VOID DeleteDevice(VOID);
NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID AddMessageToBuffer(PALPC_MONITOR_MESSAGE Message);
BOOLEAN GetMessageFromBuffer(PALPC_MONITOR_MESSAGE Message);
NTSTATUS InstallHook(VOID);
VOID UninstallHook(VOID);
#pragma warning(push)
#pragma warning(disable:4210) // nonstandard extension used : function given file scope
extern NTSYSAPI USHORT NTAPI RtlCaptureStackBackTrace(
    _In_         ULONG FramesToSkip,
    _In_         ULONG FramesToCapture,
    _Out_writes_to_(FramesToCapture, return) PVOID* BackTrace,
    _Out_opt_    PULONG BackTraceHash);
#pragma warning(pop)

NTSYSAPI PCHAR NTAPI PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

typedef struct _PORT_MESSAGE {
    union {
        struct {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES {
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_COMMUNICATION_INFO {
    PVOID ConnectionPort;
    PVOID ServerCommunicationPort;
    PVOID ClientCommunicationPort;
    LIST_ENTRY CommunicationList;
    PVOID CallbackObject;
    PVOID CallbackContext;
} ALPC_COMMUNICATION_INFO, * PALPC_COMMUNICATION_INFO;

typedef struct _ALPC_PORT {
    LIST_ENTRY PortListEntry;
    PALPC_COMMUNICATION_INFO CommunicationInfo;
    PVOID OwnerProcess;
    PVOID CompletionPort;
    PVOID CompletionKey;
    PVOID CompletionPacketLookaside;
    PVOID PortContext;
    PVOID StaticSecurity;
    PVOID IncomingQueuePort;
    PVOID MainQueue;
    PVOID LargeMessageQueue;
    PVOID PendingQueue;
    PVOID CanceledQueue;
    PVOID WaitQueue;
    PVOID Semaphore;
    PVOID DummyEvent;
    PVOID AlpcpPortLock;
    ULONG Flags;
    ULONG PortAttributes;
    EX_PUSH_LOCK Lock;
    BOOLEAN Initialized;
    BOOLEAN Closed;
    UCHAR Reserved[2];
} ALPC_PORT, * PALPC_PORT;

typedef struct _OBJECT_HEADER {
    LONG_PTR PointerCount;
    union {
        LONG_PTR HandleCount;
        PVOID NextToFree;
    };
    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;
    UCHAR TraceFlags;
    UCHAR InfoMask;
    UCHAR Flags;
    ULONG Reserved;
    PVOID QuotaBlockCharged;
    PVOID SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, * POBJECT_HEADER;

typedef struct _OBJECT_HEADER_NAME_INFO {
    PVOID Directory;
    UNICODE_STRING Name;
    LONG ReferenceCount;
} OBJECT_HEADER_NAME_INFO, * POBJECT_HEADER_NAME_INFO;

// RPC message detection
typedef struct _RPC_MESSAGE_HEADER {
    ULONG RpcType;
    ULONG Unknown1;
    ULONG Unknown2;
    ULONG RequestId;
    ULONG Unknown3;
    ULONG MethodNumber;
} RPC_MESSAGE_HEADER, * PRPC_MESSAGE_HEADER;

typedef NTSTATUS(NTAPI* PNtAlpcSendWaitReceivePort)(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN PPORT_MESSAGE SendMessage OPTIONAL,
    IN PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
    OUT PSIZE_T BufferLength OPTIONAL,
    OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL
    );

PNtAlpcSendWaitReceivePort g_OriginalNtAlpcSendWaitReceivePort = NULL;
PVOID g_NtAlpcSendWaitReceivePortAddress = NULL;
BOOLEAN g_HookInstalled = FALSE;
PMDL g_Mdl = NULL;
PVOID g_MappedAddress = NULL;
SIZE_T g_OriginalCodeLength = 0;
ULONG g_NtAlpcSsn = (ULONG)-1;

typedef struct _SYSTEM_SERVICE_TABLE {
    PULONG ServiceTableBase;        // Pointer to KiServiceTable (array of offsets on x64)
    PULONG ServiceCounterTableBase; // Pointer to service counter table
    ULONGLONG NumberOfServices;     // Number of services in the table
    PVOID ParamTableBase;           // Pointer to KiArgumentTable
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

VOID AddMessageToBuffer(PALPC_MONITOR_MESSAGE Message) {
    KIRQL OldIrql;

    KeAcquireSpinLock(&g_MessageBuffer.Lock, &OldIrql);

    // Add message to circular buffer
    RtlCopyMemory(&g_MessageBuffer.Messages[g_MessageBuffer.WriteIndex],
        Message, sizeof(ALPC_MONITOR_MESSAGE));

    g_MessageBuffer.WriteIndex = (g_MessageBuffer.WriteIndex + 1) % MESSAGE_BUFFER_SIZE;

    // Handle buffer overflow
    if (g_MessageBuffer.WriteIndex == g_MessageBuffer.ReadIndex) {
        g_MessageBuffer.ReadIndex = (g_MessageBuffer.ReadIndex + 1) % MESSAGE_BUFFER_SIZE;
    }

    KeReleaseSpinLock(&g_MessageBuffer.Lock, OldIrql);

    // Signal event
    KeSetEvent(&g_MessageBuffer.DataAvailableEvent, IO_NO_INCREMENT, FALSE);
}

BOOLEAN GetMessageFromBuffer(PALPC_MONITOR_MESSAGE Message) {
    KIRQL OldIrql;
    BOOLEAN Result = FALSE;

    KeAcquireSpinLock(&g_MessageBuffer.Lock, &OldIrql);

    if (g_MessageBuffer.ReadIndex != g_MessageBuffer.WriteIndex) {
        RtlCopyMemory(Message, &g_MessageBuffer.Messages[g_MessageBuffer.ReadIndex],
            sizeof(ALPC_MONITOR_MESSAGE));
        g_MessageBuffer.ReadIndex = (g_MessageBuffer.ReadIndex + 1) % MESSAGE_BUFFER_SIZE;
        Result = TRUE;
    }

    KeReleaseSpinLock(&g_MessageBuffer.Lock, OldIrql);

    return Result;
}

NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject) {
    NTSTATUS Status;
    UNICODE_STRING DeviceName, SymlinkName;

    RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&SymlinkName, SYMLINK_NAME);

    Status = IoCreateDevice(DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(g_DeviceObject);
        return Status;
    }

    KeInitializeSpinLock(&g_MessageBuffer.Lock);
    KeInitializeEvent(&g_MessageBuffer.DataAvailableEvent, NotificationEvent, FALSE);

    return STATUS_SUCCESS;
}

VOID DeleteDevice(VOID) {
    UNICODE_STRING SymlinkName;

    RtlInitUnicodeString(&SymlinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&SymlinkName);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Information = 0;

    switch (IrpStack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_ALPC_SET_SSN:
        if (g_HookInstalled) {
            DbgPrint("[ALPC] Cannot set SSN while hook is active.\n");
            Status = STATUS_INVALID_DEVICE_STATE;
            break;
        }
        if (IrpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        g_NtAlpcSsn = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        DbgPrint("[ALPC] Received SSN for NtAlpcSendWaitReceivePort: %lu\n", g_NtAlpcSsn);
        Status = STATUS_SUCCESS;
        break;

    case IOCTL_ALPC_START_MONITORING:
        if (g_NtAlpcSsn == (ULONG)-1) {
            DbgPrint("[ALPC] Error: Monitoring started before SSN was set by the client.\n");
            Status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        if (!g_HookInstalled) {
            Status = InstallHook();
            if (!NT_SUCCESS(Status)) {
                DbgPrint("[ALPC] Failed to install hook: 0x%08X\n", Status);
                break;
            }
        }

        g_MessageBuffer.MonitoringActive = TRUE;
        DbgPrint("[ALPC] Monitoring started\n");
        break;

    case IOCTL_ALPC_STOP_MONITORING:
        g_MessageBuffer.MonitoringActive = FALSE;

        if (g_HookInstalled) {
            UninstallHook();
        }

        DbgPrint("[ALPC] Monitoring stopped\n");
        break;

    case IOCTL_ALPC_GET_MESSAGE:
        if (IrpStack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ALPC_MONITOR_MESSAGE)) {
            PALPC_MONITOR_MESSAGE OutputBuffer = (PALPC_MONITOR_MESSAGE)Irp->AssociatedIrp.SystemBuffer;

            if (GetMessageFromBuffer(OutputBuffer)) {
                Information = sizeof(ALPC_MONITOR_MESSAGE);
            }
            else {
                Status = STATUS_NO_MORE_ENTRIES;
            }
        }
        else {
            Status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

ULONG CaptureCallStack(PVOID* StackFrames, ULONG MaxFrames) {
    ULONG FramesCaptured = 0;

    RtlZeroMemory(StackFrames, MaxFrames * sizeof(PVOID));
    __try {
        FramesCaptured = RtlCaptureStackBackTrace(
            0,              // FramesToSkip
            MaxFrames,      // FramesToCapture
            StackFrames,    // BackTrace buffer
            NULL            // BackTraceHash (optional)
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[ALPC] Exception capturing stack trace\n");
        FramesCaptured = 0;
    }

    return FramesCaptured;
}

VOID LogAlpcMessage(PPORT_MESSAGE Message, BOOLEAN IsSend) {
    ALPC_MONITOR_MESSAGE MonitorMessage = { 0 };
    PEPROCESS Process = PsGetCurrentProcess();
    PCHAR ProcessName = PsGetProcessImageFileName(Process);

    KeQuerySystemTime(&MonitorMessage.Timestamp);
    MonitorMessage.ProcessId = HandleToUlong(PsGetCurrentProcessId());
    MonitorMessage.ThreadId = HandleToUlong(PsGetCurrentThreadId());
    MonitorMessage.IsSend = IsSend;
    MonitorMessage.MessageId = Message->MessageId;
    MonitorMessage.MessageType = Message->u2.s2.Type;
    MonitorMessage.DataLength = Message->u1.s1.DataLength;
    MonitorMessage.TotalLength = Message->u1.s1.TotalLength;

    RtlStringCbCopyA(MonitorMessage.ProcessName, sizeof(MonitorMessage.ProcessName), (char*)ProcessName);

    MonitorMessage.StackFrameCount = CaptureCallStack(
        MonitorMessage.StackFrames,
        MAX_STACK_FRAMES
    );

    // Copy message data
    if (Message->u1.s1.DataLength > 0) {
        ULONG CopySize = min(Message->u1.s1.DataLength, sizeof(MonitorMessage.Data));
        __try {
            RtlCopyMemory(MonitorMessage.Data, (PUCHAR)Message + sizeof(PORT_MESSAGE), CopySize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    AddMessageToBuffer(&MonitorMessage);
}

PULONGLONG GetSSDT()
{
    ULONGLONG  KiSystemCall64 = __readmsr(0xC0000082);		// Get the address of nt!KeSystemCall64
    ULONGLONG  KiSystemServiceRepeat = 0;
    INT32 Limit = 4096;

    for (int i = 0; i < Limit; i++) {						// Increase that address until you hit "0x4c/0x8d/0x15"
        if (*(PUINT8)(KiSystemCall64 + i) == 0x4C
            && *(PUINT8)(KiSystemCall64 + i + 1) == 0x8D
            && *(PUINT8)(KiSystemCall64 + i + 2) == 0x15)
        {
            KiSystemServiceRepeat = KiSystemCall64 + i;
            DbgPrint("[ALPC] KiSystemCall64           %p \r\n", KiSystemCall64);
            DbgPrint("[ALPC] KiSystemServiceRepeat    %p \r\n", KiSystemServiceRepeat);

            // Convert relative address to absolute address
            return (PULONGLONG)(*(PINT32)(KiSystemServiceRepeat + 3) + KiSystemServiceRepeat + 7);
        }
    }

    return 0;
}

PVOID GetSsdtRoutineAddress(ULONG SystemServiceNumber)
{
    // Access the native SSDT from the service descriptor table
    PSYSTEM_SERVICE_TABLE pSSDT = (PSYSTEM_SERVICE_TABLE)GetSSDT();

    if (!pSSDT || !pSSDT->ServiceTableBase)
    {
        DbgPrint("[ALPC] Native SSDT not accessible.\n");
        return NULL;
    }

    if (SystemServiceNumber >= pSSDT->NumberOfServices)
    {
        DbgPrint("[ALPC] System service number %lu exceeds table size %llu.\n",
            SystemServiceNumber, pSSDT->NumberOfServices);
        return NULL;
    }

    // Get the offset from the service table
    PLONG ServiceTable = (PLONG)pSSDT->ServiceTableBase;
    LONG offset = ServiceTable[SystemServiceNumber];

    // Extract the routine offset (upper bits, shift right by 4)
    LONG routineOffset = offset >> 4;

    // Calculate the absolute address
    PVOID absoluteAddress = (PVOID)((ULONG_PTR)ServiceTable + routineOffset);

    return absoluteAddress;
}

NTSTATUS HookedNtAlpcSendWaitReceivePort(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN PPORT_MESSAGE SendMessage OPTIONAL,
    IN PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
    OUT PSIZE_T BufferLength OPTIONAL,
    OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL
) {
    if (SendMessage) {
        __try {
            LogAlpcMessage(SendMessage, TRUE);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[ALPC] Exception in send logging\n");
        }
    }

    NTSTATUS status = g_OriginalNtAlpcSendWaitReceivePort(
        PortHandle, Flags, SendMessage, SendMessageAttributes,
        ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout
    );

    // Log receive message
    if (NT_SUCCESS(status) && ReceiveMessage && BufferLength && *BufferLength > 0) {
        __try {
            LogAlpcMessage(ReceiveMessage, FALSE);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[ALPC] Exception in receive logging\n");
        }
    }

    return status;
}

// The hook control flow is as follows:
//
// 1. AN APPLICATION CALLS NtAlpcSendWaitReceivePort:
//    - The stack contains the return address pointing back to the application code.
//
// 2. THE HOOK PATCH REDIRECTS EXECUTION:
//    - The patch at the start of NtAlpcSendWaitReceivePort immediately transfers control to our hook handler:
//      HookedNtAlpcSendWaitReceivePor, using a jmp.
//
// 3. HookedNtAlpcSendWaitReceivePort:
//    - Log.
//    - Call the trampoline g_OriginalNtAlpcSendWaitReceivePort.
//
// 4. THE CALL TO THE TRAMPOLINE:
//    - The 'CALL g_OriginalNtAlpcSendWaitReceivePort' instruction pushes a new
//      return address onto the stack. This address points back into our
//      HookedNtAlpcSendWaitReceivePort handler (to the code after the call).
//
// 5. THE TRAMPOLINE EXECUTES:
//    - The trampoline:
//      a. Executes the original function bytes that we overwrote.
//      b. JMPs to the rest of the original NtAlpcSendWaitReceivePort
//         function, right after the part we overwrote.
//
// 6. THE ORIGINAL FUNCTION FINISHES (RET #1):
//    - The original NtAlpcSendWaitReceivePort function completes and hits its
//      final 'RET' instruction.
//    - This RET pops the return address placed on the stack in step 4, returning
//      control back to our HookedNtAlpcSendWaitReceivePort handler.
//
// 7. BACK IN THE HOOK HANDLER::
//    - Some more logging.
//    - Executes its own 'RET' instruction. This second RET pops the
//      original return address (from step 1) off the stack, and control returns
//      cleanly to the application that initiated the call.

NTSTATUS InstallHook(VOID) {
    // Use the SSN received from the usermode app instead of a hardcoded value.
    if (g_NtAlpcSsn == (ULONG)-1) {
        DbgPrint("[ALPC] Hook installation failed: SSN not set.\n");
        return STATUS_INVALID_DEVICE_STATE;
    }
    g_NtAlpcSendWaitReceivePortAddress = GetSsdtRoutineAddress(g_NtAlpcSsn);

    if (!g_NtAlpcSendWaitReceivePortAddress) {
        DbgPrint("[ALPC] Failed to get function address from SSDT for SSN %lu\n", g_NtAlpcSsn);
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("[ALPC] Installing hook at %p for SSN %lu\n", g_NtAlpcSendWaitReceivePortAddress, g_NtAlpcSsn);

    // Initialize Zydis decoder and formatter
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
        return STATUS_DRIVER_INTERNAL_ERROR;

    ZydisFormatter formatter;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
        return STATUS_DRIVER_INTERNAL_ERROR;

    SIZE_T readOffset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus status;
    CHAR printBuffer[128];

    // Start the decode loop
    while (readOffset < JUMP_TO_HOOK_SHELL_LENGTH)
    {
        status = ZydisDecoderDecodeFull(&decoder,
            (PVOID)((uintptr_t)g_NtAlpcSendWaitReceivePortAddress + readOffset), 20, &instruction,
            operands);

        if (status == ZYDIS_STATUS_NO_MORE_DATA)
        {
            return STATUS_DRIVER_INTERNAL_ERROR;
        }

        NT_ASSERT(ZYAN_SUCCESS(status));
        if (!ZYAN_SUCCESS(status))
        {
            readOffset++;
            continue;
        }

        // Format and print the instruction
        const ZyanU64 instrAddress = (ZyanU64)(((uintptr_t)g_NtAlpcSendWaitReceivePortAddress + readOffset));
        ZydisFormatterFormatInstruction(
            &formatter, &instruction, operands, instruction.operand_count_visible, printBuffer,
            sizeof(printBuffer), instrAddress, NULL);
        DbgPrint("+%-4X 0x%-16llX\t\t%hs\n", (ULONG)readOffset, instrAddress, printBuffer);

        readOffset += instruction.length;
    }

    g_OriginalCodeLength = readOffset;

    DbgPrint("[ALPC] Determined hook length to be %zu bytes.\n", g_OriginalCodeLength);
    
    UCHAR JmpCode[MAX_JUMP_CODE_LENGTH] = { 0 }; 

    // Allocate trampoline
    g_OriginalNtAlpcSendWaitReceivePort = (PNtAlpcSendWaitReceivePort)
        ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, g_OriginalCodeLength
            + JUMP_TO_ORIGINAL_CODE_SHELL_LENGTH, 'cplA');
    if (!g_OriginalNtAlpcSendWaitReceivePort) {
        DbgPrint("[ALPC] Failed to allocate trampoline memory for %s\n", "NtAlpcSendWaitReceivePort");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Create MDL
    g_Mdl = IoAllocateMdl(g_NtAlpcSendWaitReceivePortAddress, (ULONG)g_OriginalCodeLength,
        FALSE, FALSE, NULL);
    if (!g_Mdl) {
        DbgPrint("[ALPC] Failed to allocate MDL in order to modify original %s\n", "NtAlpcSendWaitReceivePort");
        ExFreePoolWithTag(g_OriginalNtAlpcSendWaitReceivePort, 'cplA');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool(g_Mdl);
    g_MappedAddress = MmMapLockedPagesSpecifyCache(g_Mdl, KernelMode,
        MmNonCached, NULL, FALSE, HighPagePriority);

    if (!g_MappedAddress) {
        DbgPrint("[ALPC] Failed to change permissions for MDL for %s\n", "NtAlpcSendWaitReceivePort");
        IoFreeMdl(g_Mdl);
        ExFreePoolWithTag(g_OriginalNtAlpcSendWaitReceivePort, 'cplA');
        return STATUS_UNSUCCESSFUL;
    }

    // Copy original bytes
    RtlCopyMemory(g_OriginalNtAlpcSendWaitReceivePort,
        g_NtAlpcSendWaitReceivePortAddress, g_OriginalCodeLength); // g_OriginalNtAlpcSendWaitReceivePort will be called from the hook function after logging

    // Create jump: mov rax, HookedNtAlpcSendWaitReceivePort; jmp rax
    JmpCode[0] = 0x48;
    JmpCode[1] = 0xB8;
    *(PVOID*)(&JmpCode[2]) = HookedNtAlpcSendWaitReceivePort;
    JmpCode[10] = 0xFF;
    JmpCode[11] = 0xE0;

    RtlCopyMemory(g_MappedAddress, JmpCode, g_OriginalCodeLength);

    // Create trampoline to continue NtAlpcSendWaitReceivePort after override
    PUCHAR TrampolineJump = (PUCHAR)g_OriginalNtAlpcSendWaitReceivePort + g_OriginalCodeLength;
    // JMP QWORD PTR [RIP+0]
    TrampolineJump[0] = 0xFF;
    TrampolineJump[1] = 0x25;
    *(PULONG)(&TrampolineJump[2]) = 0;
    PVOID targetAddress = (PUCHAR)g_NtAlpcSendWaitReceivePortAddress + g_OriginalCodeLength;
    *(PVOID*)(&TrampolineJump[6]) = targetAddress;

    g_HookInstalled = TRUE;
    DbgPrint("[ALPC] Hook installed successfully\n");

    return STATUS_SUCCESS;
}

VOID UninstallHook(VOID) {
    if (!g_HookInstalled || !g_MappedAddress) {
        return;
    }

    RtlCopyMemory(g_MappedAddress, g_OriginalNtAlpcSendWaitReceivePort, g_OriginalCodeLength);

    if (g_Mdl) {
        MmUnmapLockedPages(g_MappedAddress, g_Mdl);
        IoFreeMdl(g_Mdl);
    }

    if (g_OriginalNtAlpcSendWaitReceivePort) {
        ExFreePoolWithTag(g_OriginalNtAlpcSendWaitReceivePort, 'cplA');
    }

    g_HookInstalled = FALSE;
    g_MappedAddress = NULL;
    g_OriginalNtAlpcSendWaitReceivePort = NULL;
    g_Mdl = NULL;
    g_OriginalCodeLength = 0;

    DbgPrint("[ALPC] Hook uninstalled\n");
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    DeleteDevice();

    DbgPrint("[ALPC] Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status;

    DbgPrint("[ALPC] ALPC Monitor Driver with GUI Support\n");

    DriverObject->DriverUnload = UnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    Status = CreateDevice(DriverObject);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[ALPC] Failed to create device: 0x%08X\n", Status);
        return Status;
    }

    DbgPrint("[ALPC] Driver loaded successfully\n");

    return STATUS_SUCCESS;
}