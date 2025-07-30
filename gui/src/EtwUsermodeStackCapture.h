#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <string>
#include <tuple>
#include <thread>
#include <functional>
#include <strsafe.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// Key for correlating stacks: ProcessId, ThreadId, MessageId
// Only ThreadId is used eventually in a FIFO way (MessageId doesn't come from ETW :( )
struct StackCorrelationKey {
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG MessageId;

    bool operator==(const StackCorrelationKey& other) const {
        return ProcessId == other.ProcessId &&
            ThreadId == other.ThreadId &&
            MessageId == other.MessageId;
    }
};

// Hash function for the correlation key
struct StackCorrelationKeyHash {
    std::size_t operator()(const StackCorrelationKey& key) const {
        // Simple hash combination
        std::size_t h1 = std::hash<ULONG>{}(key.ProcessId);
        std::size_t h2 = std::hash<ULONG>{}(key.ThreadId);
        std::size_t h3 = std::hash<ULONG>{}(key.MessageId);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

// Structure to hold pending kernel stack info
struct PendingStackInfo {
    LARGE_INTEGER Timestamp;
    std::vector<PVOID> KernelFrames;
    LARGE_INTEGER QueueTime;  // When this was queued (for cleanup)
};

class EtwUsermodeStackCapture {
private:
    TRACEHANDLE m_SessionHandle;
    TRACEHANDLE m_ConsumerHandle;
    EVENT_TRACE_PROPERTIES* m_pSessionProperties;
    std::wstring m_SessionName;
    bool m_Running;
    std::thread m_ConsumerThread;

    // Pending kernel stacks waiting for ETW usermode stacks
    std::unordered_map<StackCorrelationKey, PendingStackInfo, StackCorrelationKeyHash> m_PendingStacks;
    std::mutex m_StackMutex;

    // Callback for combined stack
    std::function<void(const StackCorrelationKey&, const std::vector<PVOID>&, const std::vector<PVOID>&)> m_StackCallback;

    static VOID WINAPI ProcessEvent(PEVENT_RECORD pEvent);
    static EtwUsermodeStackCapture* s_Instance;

public:
    EtwUsermodeStackCapture();
    ~EtwUsermodeStackCapture();

    bool StartCapture(const std::function<void(const StackCorrelationKey&,
        const std::vector<PVOID>&,  // kernel frames
        const std::vector<PVOID>&)>& callback); // user frames
    void StopCapture();

    // Store kernel stack from driver to be combined with ETW usermode stack
    void AddKernelStack(ULONG ProcessId, ULONG ThreadId, ULONG MessageId,
        const LARGE_INTEGER& Timestamp, PVOID* Frames, ULONG FrameCount);

    bool IsRunning() const { return m_Running; }
};