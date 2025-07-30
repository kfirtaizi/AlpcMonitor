#include "EtwUsermodeStackCapture.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <strsafe.h>
#include <thread>

#pragma comment(lib, "advapi32.lib")

EtwUsermodeStackCapture* EtwUsermodeStackCapture::s_Instance = nullptr;

// Stack walk task GUID
// {def2fe46-7bd6-4b80-bd94-f57fe20d0ce3}
static const GUID StackWalkTaskGuid =
{ 0xdef2fe46, 0x7bd6, 0x4b80, { 0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3 } };

// ALPC task GUID  
// {45d8cccd-539f-4b72-a8b7-5c683142609a}
static const GUID ALPCTaskGuid =
{ 0x45d8cccd, 0x539f, 0x4b72, { 0xa8, 0xb7, 0x5c, 0x68, 0x31, 0x42, 0x60, 0x9a } };

EtwUsermodeStackCapture::EtwUsermodeStackCapture()
    : m_SessionHandle(0)
    , m_ConsumerHandle(0)
    , m_pSessionProperties(nullptr)
    , m_Running(false) {
    s_Instance = this;
}

EtwUsermodeStackCapture::~EtwUsermodeStackCapture() {
    StopCapture();
    if (m_pSessionProperties) {
        free(m_pSessionProperties);
    }
    s_Instance = nullptr;
}

bool EtwUsermodeStackCapture::StartCapture(
    const std::function<void(const StackCorrelationKey&,
        const std::vector<PVOID>&,
        const std::vector<PVOID>&)>& callback) {
    if (m_Running) {
        return false;
    }

    m_StackCallback = callback;

    // Must be NT Kernel Logger to work
    m_SessionName = L"NT Kernel Logger";

    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (m_SessionName.length() + 1) * sizeof(WCHAR);
    m_pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!m_pSessionProperties) {
        return false;
    }

    ZeroMemory(m_pSessionProperties, bufferSize);
    m_pSessionProperties->Wnode.BufferSize = bufferSize;
    m_pSessionProperties->Wnode.Guid = GUID_NULL;
    m_pSessionProperties->Wnode.ClientContext = 1;
    m_pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    m_pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    m_pSessionProperties->MaximumFileSize = 0;
    m_pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    m_pSessionProperties->LogFileNameOffset = 0;
    m_pSessionProperties->FlushTimer = 1;
    m_pSessionProperties->BufferSize = 64;
    m_pSessionProperties->MinimumBuffers = 4;
    m_pSessionProperties->MaximumBuffers = 128;

    StringCchCopyW((LPWSTR)((BYTE*)m_pSessionProperties + m_pSessionProperties->LoggerNameOffset),
        m_SessionName.length() + 1, m_SessionName.c_str());

    // Start trace session
    ULONG status = StartTraceW(&m_SessionHandle, m_SessionName.c_str(), m_pSessionProperties);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        free(m_pSessionProperties);
        m_pSessionProperties = nullptr;
        return false;
    }

    if (status == ERROR_ALREADY_EXISTS) {
        // Stop the existing session
        ControlTraceW(0, m_SessionName.c_str(), m_pSessionProperties, EVENT_TRACE_CONTROL_STOP);

        // Try to start again
        status = StartTraceW(&m_SessionHandle, m_SessionName.c_str(), m_pSessionProperties);
        if (status != ERROR_SUCCESS) {
            free(m_pSessionProperties);
            m_pSessionProperties = nullptr;
            return false;
        }
    }

    CLASSIC_EVENT_ID eventIds[] = {
        {ALPCTaskGuid, 33, 0},   // ALPC Send Message (0x21)
        {ALPCTaskGuid, 34, 0},   // ALPC Receive Message (0x22)
        {ALPCTaskGuid, 35, 0},   // ALPC Wait For Reply (0x23)
        {ALPCTaskGuid, 36, 0},   // ALPC Wait For New Message (0x24)
        {ALPCTaskGuid, 37, 0},   // ALPC Unwait (0x25)
    };

    // Enable stack traces for ALPC
    status = TraceSetInformation(m_SessionHandle,
        TraceStackTracingInfo,
        eventIds,
        sizeof(eventIds));

    if (status != ERROR_SUCCESS) {
        WCHAR errMsg[256];
        swprintf_s(errMsg, L"Failed to enable stack tracing: 0x%x\n", status);
        OutputDebugStringW(errMsg);
    }

    ULONG SystemTraceFlags[8];
    ZeroMemory(SystemTraceFlags, sizeof(SystemTraceFlags));
    SystemTraceFlags[0] = EVENT_TRACE_FLAG_ALPC;

    // Enable ALPC events in the kernel provider
    status = TraceSetInformation(m_SessionHandle,
        TraceSystemTraceEnableFlagsInfo,
        SystemTraceFlags,
        sizeof(SystemTraceFlags));

    if (status != ERROR_SUCCESS) {
        WCHAR errMsg[256];
        swprintf_s(errMsg, L"Failed to enable ALPC tracing: 0x%x\n", status);
        OutputDebugStringW(errMsg);
    }

    m_Running = true;

    m_ConsumerThread = std::thread([this]() {
        EVENT_TRACE_LOGFILEW traceLog = { 0 };
        traceLog.LoggerName = (LPWSTR)m_SessionName.c_str();
        traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
        traceLog.EventRecordCallback = ProcessEvent;

        m_ConsumerHandle = OpenTraceW(&traceLog);
        if (m_ConsumerHandle != INVALID_PROCESSTRACE_HANDLE) {
            WCHAR msg[256];
            swprintf_s(msg, L"OpenTraceW succeeded, handle: 0x%p\n", m_ConsumerHandle);
            OutputDebugStringW(msg);

            ULONG status = ProcessTrace(&m_ConsumerHandle, 1, nullptr, nullptr);
            swprintf_s(msg, L"ProcessTrace returned: 0x%x, GetLastError: 0x%x\n",
                status, GetLastError());
            OutputDebugStringW(msg);

            CloseTrace(m_ConsumerHandle);
        }
        else {
            WCHAR msg[256];
            swprintf_s(msg, L"OpenTraceW failed! Error: 0x%x\n", GetLastError());
            OutputDebugStringW(msg);
        }
        });

    return true;
}

void EtwUsermodeStackCapture::StopCapture() {
    if (!m_Running) {
        return;
    }

    m_Running = false;

    if (m_SessionHandle != 0) {
        ControlTraceW(m_SessionHandle, m_SessionName.c_str(), m_pSessionProperties, EVENT_TRACE_CONTROL_STOP);
        m_SessionHandle = 0;
    }

    // Wait for consumer thread
    if (m_ConsumerThread.joinable()) {
        m_ConsumerThread.join();
    }
}

void EtwUsermodeStackCapture::AddKernelStack(ULONG ProcessId, ULONG ThreadId, ULONG MessageId,
    const LARGE_INTEGER& Timestamp, PVOID* Frames, ULONG FrameCount) {
    std::lock_guard<std::mutex> lock(m_StackMutex);

    StackCorrelationKey key = { ProcessId, ThreadId, MessageId };
    PendingStackInfo& info = m_PendingStacks[key];

    info.Timestamp = Timestamp;
    info.KernelFrames.clear();
    info.KernelFrames.reserve(FrameCount);

    for (ULONG i = 0; i < FrameCount; i++) {
        info.KernelFrames.push_back(Frames[i]);
    }

    // Record when this was queued
    QueryPerformanceCounter(&info.QueueTime);
}

VOID WINAPI EtwUsermodeStackCapture::ProcessEvent(PEVENT_RECORD pEvent) {
    if (!s_Instance || !s_Instance->m_Running) {
        return;
    }

    // Check if this is a stack walk event
    if (IsEqualGUID(pEvent->EventHeader.ProviderId, StackWalkTaskGuid)) {
        if (pEvent->EventHeader.EventDescriptor.Opcode == 32) {
            ULONG threadId = pEvent->EventHeader.ThreadId;
            ULONG processId = pEvent->EventHeader.ProcessId;

            if (pEvent->UserDataLength < sizeof(ULONG64) + sizeof(ULONG) + sizeof(ULONG)) {
                return;
            }

            // Parse the event data
            BYTE* pData = (BYTE*)pEvent->UserData;
            ULONG64 eventTimestamp = *(ULONG64*)pData; pData += sizeof(ULONG64);
            ULONG eventProcessId = *(ULONG*)pData; pData += sizeof(ULONG);
            ULONG eventThreadId = *(ULONG*)pData; pData += sizeof(ULONG);

            // Calculate number of stack frames
            ULONG remainingBytes = pEvent->UserDataLength - (sizeof(ULONG64) + sizeof(ULONG) + sizeof(ULONG));
            ULONG frameCount = remainingBytes / sizeof(PVOID);
            PVOID* frames = (PVOID*)pData;

            // Extract only usermode frames
            std::vector<PVOID> userFrames;
            userFrames.reserve(frameCount);

            for (ULONG i = 0; i < frameCount; i++) {
                ULONG_PTR addr = (ULONG_PTR)frames[i];

                // On x64, kernel addresses start at 0xFFFF800000000000
                // On x86, kernel addresses start at 0x80000000
#ifdef _WIN64
                if (addr < 0xFFFF800000000000) {
                    userFrames.push_back(frames[i]);
                }
#else
                if (addr < 0x80000000) {
                    userFrames.push_back(frames[i]);
                }
#endif
            }

            std::lock_guard<std::mutex> lock(s_Instance->m_StackMutex);

            // Find and remove the most recent pending stack for this thread
            PendingStackInfo* foundStack = nullptr;
            StackCorrelationKey foundKey;

            for (auto it = s_Instance->m_PendingStacks.begin();
                it != s_Instance->m_PendingStacks.end(); ++it) {

                if (it->first.ThreadId == eventThreadId) {
                    // Found a matching thread - take this entry
                    foundStack = &it->second;
                    foundKey = it->first;

                    // Invoke callback with the matched data
                    if (s_Instance->m_StackCallback) {
                        s_Instance->m_StackCallback(foundKey,
                            foundStack->KernelFrames,
                            userFrames);
                    }

                    // Remove from pending
                    s_Instance->m_PendingStacks.erase(it);
                    break;
                }
            }
        }
    }
}