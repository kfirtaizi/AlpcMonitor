#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <dbghelp.h>
#include <mutex>
#include <queue>
#include <unordered_map>
#include <psapi.h>
#include <winternl.h>
#include <fstream>
#include "AlpcMonitorGUI.h"
#include "FilterEngine.h"
#include <stack>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define MAX_PENDING_MESSAGES 100000
#define BATCH_UPDATE_INTERVAL 25
#define MAX_BATCH_SIZE 500

struct CombinedStack {
    std::vector<PVOID> KernelFrames;
    std::vector<PVOID> UserFrames;
};

// Kernel module structures for NtQuerySystemInformation
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
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

class KernelAddressResolver {
private:
    struct ModuleInfo {
        PVOID BaseAddress;
        ULONG Size;
        std::string ModuleName;
        std::string FullPath;
    };

    std::vector<ModuleInfo> m_modules;
    std::unordered_map<PVOID, std::string> m_cache;
    std::mutex m_cacheMutex;
    PNtQuerySystemInformation m_NtQuerySystemInformation;
    bool m_initialized;

public:
    KernelAddressResolver() : m_initialized(false) {
        m_NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    }

    bool Initialize() {
        if (!m_NtQuerySystemInformation) {
            return false;
        }

        // Try to enable SeDebugPrivilege (required on Windows 11 24H2+)
        EnableDebugPrivilege();

        return RefreshModuleList();
    }

    bool RefreshModuleList() {
        ULONG bufferSize = 0;
        NTSTATUS status = m_NtQuerySystemInformation(
            SystemModuleInformation, nullptr, 0, &bufferSize);

        if (bufferSize == 0) {
            return false;
        }

        std::vector<BYTE> buffer(bufferSize);
        status = m_NtQuerySystemInformation(
            SystemModuleInformation, buffer.data(), bufferSize, &bufferSize);

        if (!NT_SUCCESS(status)) {
            return false;
        }

        PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)buffer.data();
        m_modules.clear();
        m_modules.reserve(modules->NumberOfModules);

        for (ULONG i = 0; i < modules->NumberOfModules; i++) {
            ModuleInfo info;
            info.BaseAddress = modules->Modules[i].ImageBase;
            info.Size = modules->Modules[i].ImageSize;
            info.FullPath = std::string((char*)modules->Modules[i].FullPathName);

            // Extract module name from path
            size_t pos = info.FullPath.find_last_of("\\/");
            if (pos != std::string::npos) {
                info.ModuleName = info.FullPath.substr(pos + 1);
            }
            else {
                info.ModuleName = info.FullPath;
            }

            m_modules.push_back(info);
        }

        m_initialized = true;
        return true;
    }

    std::wstring ResolveAddress(PVOID address) {
        if (!m_initialized) {
            return L"???";
        }

        // Check cache first
        {
            std::lock_guard<std::mutex> lock(m_cacheMutex);
            auto it = m_cache.find(address);
            if (it != m_cache.end()) {
                return std::wstring(it->second.begin(), it->second.end());
            }
        }

        // Find containing module
        ULONG_PTR addr = (ULONG_PTR)address;
        for (const auto& module : m_modules) {
            ULONG_PTR base = (ULONG_PTR)module.BaseAddress;
            ULONG_PTR end = base + module.Size;

            if (addr >= base && addr < end) {
                ULONG_PTR offset = addr - base;
                std::stringstream ss;
                ss << module.ModuleName << "+0x" << std::hex << offset;

                std::string result = ss.str();

                // Cache the result
                {
                    std::lock_guard<std::mutex> lock(m_cacheMutex);
                    m_cache[address] = result;
                }

                return std::wstring(result.begin(), result.end());
            }
        }

        // Not found in any module
        std::wstringstream ss;
        ss << L"0x" << std::hex << (ULONG_PTR)address;
        return ss.str();
    }

private:
    bool EnableDebugPrivilege() {
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }

        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        bool result = AdjustTokenPrivileges(hToken, FALSE, &tp,
            sizeof(TOKEN_PRIVILEGES), NULL, NULL);

        DWORD error = GetLastError();
        CloseHandle(hToken);

        return result && error != ERROR_NOT_ALL_ASSIGNED;
    }
};

// Window controls
#define ID_LISTVIEW 1001
#define ID_START_BUTTON 1002
#define ID_STOP_BUTTON 1003
#define ID_CLEAR_BUTTON 1004
#define ID_DETAILS_EDIT 1005
#define ID_FILTER_EDIT 1006
#define ID_FILTER_BUTTON 1007
#define ID_STATUSBAR 1008
#define ID_UPDATE_TIMER 1009
#define ID_STACK_FILTER_CHECKBOX 1010
#define ID_FIND_RPC_BUTTON 1011
#define ID_RPC_RESULT_LABEL 1012

// Global variables
HWND g_hWnd = NULL;
HWND g_hListView = NULL;
HWND g_hDetailsEdit = NULL;
HWND g_hStatusBar = NULL;
HWND g_hFilterEdit = NULL;
HWND g_hStackFilterCheck = NULL;
bool g_EnableStackFilter = false;
HANDLE g_hDriver = INVALID_HANDLE_VALUE;
HWND g_hFindRpcButton = NULL;
HWND g_hRpcResultLabel = NULL;

std::atomic<bool> g_MonitoringActive(false);
std::atomic<bool> g_StopRequested(false);
std::thread g_MonitorThread;
std::wstring g_FilterText;
std::vector<MessageContainer> g_Messages;
std::vector<size_t> g_FilteredIndices;
KernelAddressResolver g_KernelResolver;
EtwUsermodeStackCapture g_EtwCapture;
// Map from correlation key to combined stack
std::unordered_map<StackCorrelationKey, CombinedStack, StackCorrelationKeyHash> g_CombinedStacks;
std::mutex g_CombinedStackMutex;


std::mutex g_QueueMutex;
std::queue<ALPC_MONITOR_MESSAGE> g_MessageQueue;
std::atomic<size_t> g_DroppedMessages(0);
std::atomic<size_t> g_TotalMessages(0);
std::atomic<size_t> g_FilteredMessages(0);
int g_lastSelectedIndex = -1;


// Function prototypes
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void CreateControls(HWND hwnd);
void InitListView(HWND hListView);
void AddMessageToListView(const ALPC_MONITOR_MESSAGE& msg);
void ProcessMessageBatch();
void StartMonitoring();
void StopMonitoring();
void MonitorThreadProc();
std::wstring FormatTimestamp(const LARGE_INTEGER& timestamp);
std::wstring FormatHexDump(const UCHAR* data, USHORT length);
void UpdateStatusBar(const std::wstring& text);
void ShowMessageDetails(int index);
ResolvedStackInfo ResolveCombinedStack(const ALPC_MONITOR_MESSAGE& msg);
void ApplyFilter();
void RebuildListView();
void FindRpcCallee(int messageIndex);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize kernel address resolver
    if (!g_KernelResolver.Initialize()) {
        MessageBox(NULL, L"Failed to initialize kernel address resolver. Some features may be limited.",
            L"Warning", MB_OK | MB_ICONWARNING);
    }

    // Initialize common controls
    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icex);

    // Register window class
    const wchar_t CLASS_NAME[] = L"AlpcMonitorWindow";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);

    RegisterClass(&wc);

    // Create window
    g_hWnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"ALPC Monitor",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1400, 800,
        NULL, NULL, hInstance, NULL
    );

    if (!g_hWnd) return 0;

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        CreateControls(hwnd);
        SetTimer(hwnd, ID_UPDATE_TIMER, BATCH_UPDATE_INTERVAL, NULL);
        return 0;

    case WM_SIZE:
    {
        RECT rcClient;
        GetClientRect(hwnd, &rcClient);

        SetWindowPos(g_hListView, NULL, 5, 40, rcClient.right - 10,
            rcClient.bottom - 280, SWP_NOZORDER);
        SetWindowPos(g_hDetailsEdit, NULL, 5, rcClient.bottom - 230,
            rcClient.right - 10, 200, SWP_NOZORDER);

        SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
    }
    return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_START_BUTTON:
            StartMonitoring();
            break;
        case ID_STOP_BUTTON:
            StopMonitoring();
            break;
        case ID_CLEAR_BUTTON:
            ListView_DeleteAllItems(g_hListView);
            g_Messages.clear();
            g_FilteredIndices.clear();
            SetWindowText(g_hDetailsEdit, L"");
            SetWindowText(g_hRpcResultLabel, L"");
            SetWindowText(g_hFindRpcButton, L"Find RPC Callee");
            EnableWindow(g_hFindRpcButton, FALSE);
            {
                std::lock_guard<std::mutex> lock(g_QueueMutex);
                std::queue<ALPC_MONITOR_MESSAGE> empty;
                std::swap(g_MessageQueue, empty);
            }
            g_DroppedMessages = 0;
            g_TotalMessages = 0;
            g_FilteredMessages = 0;
            UpdateStatusBar(L"Cleared all messages");
            break;
        case ID_FILTER_BUTTON:
            ApplyFilter();
            break;
        case ID_FIND_RPC_BUTTON:
            if (g_lastSelectedIndex != -1) {
                FindRpcCallee(g_lastSelectedIndex);
            }
            break;
        }
        return 0;

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->idFrom == ID_LISTVIEW && pnmh->code == NM_CLICK) {
            LPNMITEMACTIVATE pnmia = (LPNMITEMACTIVATE)lParam;
            if (pnmia->iItem != -1) {
                // Get the actual message index from the filtered indices
                if (pnmia->iItem < (int)g_FilteredIndices.size()) {
                    ShowMessageDetails(g_FilteredIndices[pnmia->iItem]);
                }
            }
        }
    }
    return 0;

    case WM_TIMER:
        if (wParam == ID_UPDATE_TIMER) {
            ProcessMessageBatch();
        }
        return 0;

    case WM_DESTROY:
        StopMonitoring();

        if (g_hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hDriver);
            g_hDriver = INVALID_HANDLE_VALUE;
        }

        KillTimer(hwnd, ID_UPDATE_TIMER);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void CreateControls(HWND hwnd) {
    // Create toolbar buttons
    CreateWindow(L"BUTTON", L"Start Monitoring",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        5, 5, 120, 30, hwnd, (HMENU)ID_START_BUTTON, NULL, NULL);

    CreateWindow(L"BUTTON", L"Stop Monitoring",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        130, 5, 120, 30, hwnd, (HMENU)ID_STOP_BUTTON, NULL, NULL);

    CreateWindow(L"BUTTON", L"Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        255, 5, 80, 30, hwnd, (HMENU)ID_CLEAR_BUTTON, NULL, NULL);

    // Filter controls
    CreateWindow(L"STATIC", L"Filter:",
        WS_CHILD | WS_VISIBLE,
        350, 10, 40, 20, hwnd, NULL, NULL, NULL);

    g_hFilterEdit = CreateWindow(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        395, 7, 200, 25, hwnd, (HMENU)ID_FILTER_EDIT, NULL, NULL);

    SendMessage(g_hFilterEdit, EM_SETLIMITTEXT, (WPARAM)255, 0);

    g_hStackFilterCheck = CreateWindow(L"BUTTON", L"Enable callstack filtering (Slow!)",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        600, 7, 230, 25, hwnd, (HMENU)ID_STACK_FILTER_CHECKBOX, NULL, NULL);

    CreateWindow(L"BUTTON", L"Apply",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        835, 5, 60, 30, hwnd, (HMENU)ID_FILTER_BUTTON, NULL, NULL);

    g_hFindRpcButton = CreateWindow(L"BUTTON", L"Find RPC Callee",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        900, 5, 140, 30, hwnd, (HMENU)ID_FIND_RPC_BUTTON, NULL, NULL);

    g_hRpcResultLabel = CreateWindow(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        1050, 10, 600, 20, hwnd, (HMENU)ID_RPC_RESULT_LABEL, NULL, NULL);

    // Create ListView
    g_hListView = CreateWindow(WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        5, 40, 1380, 480, hwnd, (HMENU)ID_LISTVIEW, NULL, NULL);

    ListView_SetExtendedListViewStyle(g_hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    InitListView(g_hListView);

    // Create details edit control
    g_hDetailsEdit = CreateWindow(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE |
        ES_READONLY | WS_VSCROLL | WS_HSCROLL,
        5, 530, 1380, 200, hwnd, (HMENU)ID_DETAILS_EDIT, NULL, NULL);

    // Use fixed-width font for hex display
    HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    SendMessage(g_hDetailsEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Create status bar
    g_hStatusBar = CreateWindow(STATUSCLASSNAME, NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hwnd, (HMENU)ID_STATUSBAR, NULL, NULL);

    UpdateStatusBar(L"Ready");
}

void InitListView(HWND hListView) {
    LVCOLUMN lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    // Add columns
    lvc.pszText = (LPWSTR)L"Time";
    lvc.cx = 140;
    ListView_InsertColumn(hListView, 0, &lvc);

    lvc.pszText = (LPWSTR)L"Direction";
    lvc.cx = 60;
    ListView_InsertColumn(hListView, 1, &lvc);

    lvc.pszText = (LPWSTR)L"Process";
    lvc.cx = 120;
    ListView_InsertColumn(hListView, 2, &lvc);

    lvc.pszText = (LPWSTR)L"PID";
    lvc.cx = 60;
    ListView_InsertColumn(hListView, 3, &lvc);

    lvc.pszText = (LPWSTR)L"TID";
    lvc.cx = 60;
    ListView_InsertColumn(hListView, 4, &lvc);

    lvc.pszText = (LPWSTR)L"Port Handle";
    lvc.cx = 140;
    ListView_InsertColumn(hListView, 5, &lvc);

    lvc.pszText = (LPWSTR)L"Msg ID";
    lvc.cx = 80;
    ListView_InsertColumn(hListView, 6, &lvc);

    lvc.pszText = (LPWSTR)L"Type";
    lvc.cx = 60;
    ListView_InsertColumn(hListView, 7, &lvc);

    lvc.pszText = (LPWSTR)L"Data Len";
    lvc.cx = 80;
    ListView_InsertColumn(hListView, 8, &lvc);

    lvc.pszText = (LPWSTR)L"Preview";
    lvc.cx = 300;
    ListView_InsertColumn(hListView, 9, &lvc);
}

void ProcessMessageBatch() {
    if (!g_MonitoringActive && g_MessageQueue.empty()) return;

    std::vector<ALPC_MONITOR_MESSAGE> batch;
    size_t queueSize = 0;

    {
        std::lock_guard<std::mutex> lock(g_QueueMutex);
        queueSize = g_MessageQueue.size();

        size_t batchSize = MAX_BATCH_SIZE;
        if (queueSize > 20000) {
            batchSize = 2000;
        }
        else if (queueSize > 10000) {
            batchSize = 1000;
        }

        size_t count = 0;
        while (!g_MessageQueue.empty() && count < batchSize) {
            batch.push_back(g_MessageQueue.front());
            g_MessageQueue.pop();
            count++;
        }
    }

    if (batch.empty()) return;

    bool preResolveStacks = (SendMessage(g_hStackFilterCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);

    int itemCount = ListView_GetItemCount(g_hListView);
    int visibleCount = ListView_GetCountPerPage(g_hListView);
    int topIndex = ListView_GetTopIndex(g_hListView);
    bool shouldScroll = (itemCount == 0 || topIndex + visibleCount >= itemCount - 2);

    SendMessage(g_hListView, WM_SETREDRAW, FALSE, 0);

    for (const auto& msg : batch) {
        MessageContainer container;
        container.Msg = msg;
        if (preResolveStacks) {
            container.StackInfo = ResolveCombinedStack(msg);
            container.StackResolved = true;
        }
        else {
            container.StackResolved = false;
        }
        g_Messages.push_back(container);

        if (PassesFilter(g_Messages.back(), g_FilterText, preResolveStacks)) {
            g_FilteredIndices.push_back(g_Messages.size() - 1);
            AddMessageToListView(g_Messages.back().Msg);
            g_FilteredMessages++;
        }
    }

    SendMessage(g_hListView, WM_SETREDRAW, TRUE, 0);

    if (shouldScroll) {
        int newCount = ListView_GetItemCount(g_hListView);
        if (newCount > 0) {
            ListView_EnsureVisible(g_hListView, newCount - 1, FALSE);
        }
    }

    InvalidateRect(g_hListView, NULL, FALSE);

    std::wstringstream status;
    status << L"Monitoring active - Messages: " << g_TotalMessages;
    if (!g_FilterText.empty()) {
        status << L" (Filtered: " << g_FilteredMessages << L")";
    }
    if (g_DroppedMessages > 0) {
        status << L" (Dropped: " << g_DroppedMessages << L")";
    }
    {
        std::lock_guard<std::mutex> lock(g_QueueMutex);
        size_t queueSize = g_MessageQueue.size();
        if (queueSize > 0) {
            status << L" - Queue: " << queueSize;
            if (queueSize > 10000) {
                status << L" (Heavy load!)";
            }
        }
    }

    size_t memoryUsageMB = (g_Messages.size() * sizeof(ALPC_MONITOR_MESSAGE)) / (1024 * 1024);
    if (memoryUsageMB > 100) {
        status << L" - Memory: ~" << memoryUsageMB << L"MB";
    }

    UpdateStatusBar(status.str());
}

// Function to get the System Service Number (SSN) by parsing ntdll.dll
DWORD GetSvcNumber(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return 0;
    }

    FARPROC funcAddress = GetProcAddress(hNtdll, functionName);
    if (funcAddress == NULL) {
        return 0;
    }

    // On x64, the syscall stub is typically:
    // mov r10, rcx
    // mov eax, <SSN>
    unsigned char* bytecode = (unsigned char*)funcAddress;
    for (int i = 0; i < 32; ++i) {
        if (bytecode[i] == 0xB8) {
            // The 4 bytes after the opcode is the SSN
            DWORD svcNumber = *(DWORD*)(bytecode + i + 1);
            return svcNumber;
        }
    }

    return 0;
}

void StartMonitoring() {
    if (g_MonitoringActive) return;

    if (g_hDriver == INVALID_HANDLE_VALUE) {
        DWORD ssn = GetSvcNumber("NtAlpcSendWaitReceivePort");
        if (ssn == 0) {
            MessageBox(g_hWnd, L"Failed to dynamically find the system service number for NtAlpcSendWaitReceivePort. The driver cannot be started.",
                L"Error", MB_OK | MB_ICONERROR);
            return;
        }

        g_hDriver = CreateFile(L"\\\\.\\AlpcMonitor",
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL);

        if (g_hDriver == INVALID_HANDLE_VALUE) {
            MessageBox(g_hWnd, L"Failed to open driver. Make sure the driver is loaded.",
                L"Error", MB_OK | MB_ICONERROR);
            return;
        }

        DWORD bytesReturned;
        if (!DeviceIoControl(g_hDriver, IOCTL_ALPC_SET_SSN,
            &ssn, sizeof(ssn),
            NULL, 0, &bytesReturned, NULL)) {
            MessageBox(g_hWnd, L"Failed to send system service number to the driver. The driver might be incompatible or an error occurred.", L"Error", MB_OK | MB_ICONERROR);
            CloseHandle(g_hDriver);
            g_hDriver = INVALID_HANDLE_VALUE;
            return;
        }
    }

    DWORD bytesReturned;
    if (!DeviceIoControl(g_hDriver, IOCTL_ALPC_START_MONITORING,
        NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        MessageBox(g_hWnd, L"Failed to start monitoring", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Start ETW capture for usermode stacks
    bool etwStarted = g_EtwCapture.StartCapture(
        [](const StackCorrelationKey& key,
            const std::vector<PVOID>& kernelFrames,
            const std::vector<PVOID>& userFrames) {
                // Store combined stack
                std::lock_guard<std::mutex> lock(g_CombinedStackMutex);
                CombinedStack& stack = g_CombinedStacks[key];
                stack.KernelFrames = kernelFrames;
                stack.UserFrames = userFrames;
        }
    );

    if (!etwStarted) {
        MessageBox(g_hWnd, L"Failed to start ETW capture. Usermode stacks will not be available.\n"
            L"Make sure you're running as Administrator.",
            L"Warning", MB_OK | MB_ICONWARNING);
    }

    g_StopRequested = false;
    g_MonitoringActive = true;
    g_DroppedMessages = 0;
    g_TotalMessages = 0;
    g_FilteredMessages = 0;
    g_MonitorThread = std::thread(MonitorThreadProc);

    EnableWindow(GetDlgItem(g_hWnd, ID_START_BUTTON), FALSE);
    EnableWindow(GetDlgItem(g_hWnd, ID_STOP_BUTTON), TRUE);
    UpdateStatusBar(L"Monitoring active");
}

void StopMonitoring() {
    if (!g_MonitoringActive) return;

    g_StopRequested = true;
    g_MonitoringActive = false;

    // Stop ETW capture
    g_EtwCapture.StopCapture();

    if (g_hDriver != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        DeviceIoControl(g_hDriver, IOCTL_ALPC_STOP_MONITORING,
            NULL, 0, NULL, 0, &bytesReturned, NULL);
    }

    if (g_MonitorThread.joinable()) {
        g_MonitorThread.join();
    }

    ProcessMessageBatch();

    EnableWindow(GetDlgItem(g_hWnd, ID_START_BUTTON), TRUE);
    EnableWindow(GetDlgItem(g_hWnd, ID_STOP_BUTTON), FALSE);
    UpdateStatusBar(L"Monitoring stopped");
}

void MonitorThreadProc() {
    ALPC_MONITOR_MESSAGE msg;
    DWORD bytesReturned;

    while (!g_StopRequested) {
        if (DeviceIoControl(g_hDriver, IOCTL_ALPC_GET_MESSAGE,
            NULL, 0, &msg, sizeof(msg), &bytesReturned, NULL)) {

            g_TotalMessages++;

            // Store kernel stack for ETW correlation
            if (msg.StackFrameCount > 0) {
                g_EtwCapture.AddKernelStack(msg.ProcessId, msg.ThreadId, msg.MessageId,
                    msg.Timestamp, msg.StackFrames,
                    msg.StackFrameCount);
            }

            std::lock_guard<std::mutex> lock(g_QueueMutex);

            size_t currentSize = g_MessageQueue.size();
            if (currentSize < MAX_PENDING_MESSAGES) {
                g_MessageQueue.push(msg);
            }
            else {
                g_DroppedMessages++;
                PostMessage(g_hWnd, WM_TIMER, ID_UPDATE_TIMER, 0);
            }
        }
        else {
            Sleep(1);
        }
    }
}

void AddMessageToListView(const ALPC_MONITOR_MESSAGE& msg) {
    LVITEM lvi = {};
    lvi.mask = LVIF_TEXT;
    lvi.iItem = ListView_GetItemCount(g_hListView);

    // Time
    std::wstring time = FormatTimestamp(msg.Timestamp);
    lvi.pszText = (LPWSTR)time.c_str();
    ListView_InsertItem(g_hListView, &lvi);

    // Direction
    ListView_SetItemText(g_hListView, lvi.iItem, 1,
        (LPWSTR)(msg.IsSend ? L"SEND" : L"RECV"));

    // Process name
    wchar_t processName[32];
    MultiByteToWideChar(CP_ACP, 0, msg.ProcessName, -1, processName, 32);
    ListView_SetItemText(g_hListView, lvi.iItem, 2, processName);

    // PID
    wchar_t pid[32];
    swprintf_s(pid, L"%lu", msg.ProcessId);
    ListView_SetItemText(g_hListView, lvi.iItem, 3, pid);

    // TID
    wchar_t tid[32];
    swprintf_s(tid, L"%lu", msg.ThreadId);
    ListView_SetItemText(g_hListView, lvi.iItem, 4, tid);

    // PortHandle
    wchar_t portHandle[32];
    swprintf_s(portHandle, L"%lu", msg.PortHandle);
    ListView_SetItemText(g_hListView, lvi.iItem, 5, portHandle);

    // Message ID
    wchar_t msgId[32];
    swprintf_s(msgId, L"0x%08X", msg.MessageId);
    ListView_SetItemText(g_hListView, lvi.iItem, 6, msgId);

    // Type
    wchar_t type[32];
    swprintf_s(type, L"0x%04X", msg.MessageType);
    ListView_SetItemText(g_hListView, lvi.iItem, 7, type);

    // Data length
    wchar_t dataLen[32];
    swprintf_s(dataLen, L"%u", msg.DataLength);
    ListView_SetItemText(g_hListView, lvi.iItem, 8, dataLen);

    // Preview (first few bytes as text if possible)
    std::wstring preview;
    if (msg.DataLength > 0) {
        bool isText = true;
        for (int i = 0; i < min(32, msg.DataLength); i++) {
            if (msg.Data[i] < 32 && msg.Data[i] != '\r' &&
                msg.Data[i] != '\n' && msg.Data[i] != '\t') {
                isText = false;
                break;
            }
        }

        if (isText) {
            char tempStr[64] = {};
            memcpy(tempStr, msg.Data, min(60, msg.DataLength));
            wchar_t wideStr[128];
            MultiByteToWideChar(CP_ACP, 0, tempStr, -1, wideStr, 128);
            preview = wideStr;
        }
        else {
            std::wstringstream ss;
            for (int i = 0; i < min(16, msg.DataLength); i++) {
                ss << std::hex << std::setw(2) << std::setfill(L'0')
                    << (int)msg.Data[i] << L" ";
            }
            if (msg.DataLength > 16) ss << L"...";
            preview = ss.str();
        }
    }
    ListView_SetItemText(g_hListView, lvi.iItem, 9, (LPWSTR)preview.c_str());
}

std::wstring FormatTimestamp(const LARGE_INTEGER& timestamp) {
    FILETIME ft;
    ft.dwLowDateTime = timestamp.LowPart;
    ft.dwHighDateTime = timestamp.HighPart;

    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    wchar_t buffer[64];
    swprintf_s(buffer, L"%02d:%02d:%02d.%03d",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    return buffer;
}

std::wstring FormatHexDump(const UCHAR* data, USHORT length) {
    std::wstringstream ss;

    for (USHORT i = 0; i < length; i += 16) {
        // Offset
        ss << std::hex << std::setw(4) << std::setfill(L'0') << i << L": ";

        // Hex bytes
        for (USHORT j = 0; j < 16; j++) {
            if (i + j < length) {
                ss << std::hex << std::setw(2) << std::setfill(L'0')
                    << (int)data[i + j] << L" ";
            }
            else {
                ss << L"   ";
            }
        }

        ss << L" | ";

        // ASCII
        for (USHORT j = 0; j < 16 && (i + j) < length; j++) {
            UCHAR c = data[i + j];
            ss << (wchar_t)((c >= 32 && c < 127) ? c : L'.');
        }

        ss << L"\r\n";
    }

    return ss.str();
}

ResolvedStackInfo ResolveCombinedStack(const ALPC_MONITOR_MESSAGE& msg) {
    ResolvedStackInfo resolvedInfo;

    // Check for combined stack using correlation key
    StackCorrelationKey key = { msg.ProcessId, msg.ThreadId, msg.MessageId };
    CombinedStack combinedStack;
    bool hasCombinedStack = false;

    {
        std::lock_guard<std::mutex> lock(g_CombinedStackMutex);
        auto it = g_CombinedStacks.find(key);
        if (it != g_CombinedStacks.end()) {
            combinedStack = it->second;
            hasCombinedStack = true;
        }
    }

    if (hasCombinedStack) {
        // First, resolve kernel frames
        if (!combinedStack.KernelFrames.empty()) {
            for (const auto& frame : combinedStack.KernelFrames) {
                resolvedInfo.KernelStackStrings.push_back(g_KernelResolver.ResolveAddress(frame));
            }
        }

        // Then, resolve usermode frames
        if (!combinedStack.UserFrames.empty()) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, msg.ProcessId);

            bool symbolsAvailable = false;
            if (hProcess) {
                SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES |
                    SYMOPT_LOAD_ANYTHING | SYMOPT_INCLUDE_32BIT_MODULES);

                const wchar_t* symPath = L"srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols";
                char symPathA[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, symPath, -1, symPathA, MAX_PATH, NULL, NULL);

                symbolsAvailable = SymInitialize(hProcess, symPathA, TRUE) == TRUE;
            }

            // Resolve each frame into a string
            for (const auto& frame : combinedStack.UserFrames) {
                std::wstringstream frame_ss;

                if (symbolsAvailable) {
                    DWORD64 displacement = 0;
                    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
                    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
                    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                    pSymbol->MaxNameLen = MAX_SYM_NAME;
                    DWORD64 address = (DWORD64)frame;

                    if (SymFromAddr(hProcess, address, &displacement, pSymbol)) {
                        // Get module name
                        IMAGEHLP_MODULE64 module = { sizeof(IMAGEHLP_MODULE64) };
                        std::wstring moduleName;
                        if (SymGetModuleInfo64(hProcess, address, &module)) {
                            std::string modName(module.ModuleName);
                            moduleName = std::wstring(modName.begin(), modName.end());
                        }

                        // Get source file and line
                        IMAGEHLP_LINE64 line = { sizeof(IMAGEHLP_LINE64) };
                        DWORD lineDisplacement = 0;
                        bool hasLine = SymGetLineFromAddr64(hProcess, address, &lineDisplacement, &line) == TRUE;

                        // Format output
                        if (!moduleName.empty()) {
                            frame_ss << moduleName << L"!";
                        }
                        std::string symbolName(pSymbol->Name);
                        frame_ss << std::wstring(symbolName.begin(), symbolName.end());

                        if (displacement != 0) {
                            frame_ss << L"+0x" << std::hex << displacement;
                        }

                        if (hasLine) {
                            std::string fileName(line.FileName);
                            std::wstring wFileName(fileName.begin(), fileName.end());
                            size_t pos = wFileName.find_last_of(L"\\/");
                            if (pos != std::wstring::npos) {
                                wFileName = wFileName.substr(pos + 1);
                            }
                            frame_ss << L" [" << wFileName << L":" << std::dec << line.LineNumber << L"]";
                        }
                    }
                    else {
                        // Symbol resolution failed for this frame, show raw address
                        frame_ss << L"0x" << std::hex << address;
                    }
                }
                else {
                    // No symbols available, just show raw address
                    frame_ss << L"0x" << std::hex << (ULONG_PTR)frame;
                }
                resolvedInfo.UserStackStrings.push_back(frame_ss.str());
            }

            // Cleanup symbol handler
            if (symbolsAvailable) {
                SymCleanup(hProcess);
            }
            if (hProcess) {
                CloseHandle(hProcess);
            }
        }
    }
    else {
        // No combined stack available, resolve kernel stack only
        if (msg.StackFrameCount > 0) {
            for (ULONG i = 0; i < msg.StackFrameCount; i++) {
                resolvedInfo.KernelStackStrings.push_back(g_KernelResolver.ResolveAddress(msg.StackFrames[i]));
            }
        }
    }

    return resolvedInfo;
}

void ShowMessageDetails(int index) {
    if (index < 0 || index >= (int)g_Messages.size()) return;

    g_lastSelectedIndex = index;
    MessageContainer& container = g_Messages[index];
    const ALPC_MONITOR_MESSAGE& msg = container.Msg;

    switch (container.RpcState) {
    case RpcAnalysisState::NotAnalyzed:
        SetWindowText(g_hFindRpcButton, L"Find RPC Callee");
        EnableWindow(g_hFindRpcButton, TRUE);
        SetWindowText(g_hRpcResultLabel, L"");
        break;

    case RpcAnalysisState::AnalysisInProgress:
        SetWindowText(g_hFindRpcButton, L"Analyzing...");
        EnableWindow(g_hFindRpcButton, FALSE);
        SetWindowText(g_hRpcResultLabel, L"Analyzing...");
        break;

    case RpcAnalysisState::AnalysisComplete:
        SetWindowText(g_hFindRpcButton, L"Find RPC Callee");
        EnableWindow(g_hFindRpcButton, FALSE);
        SetWindowText(g_hRpcResultLabel, container.RpcAnalysisResult.c_str());
        break;
    }

    std::wstringstream left_ss, right_ss; // Use two streams for the two columns

    // --- LEFT COLUMN: Header info ---
    left_ss << L"=== ALPC Message Details ===\r\n\r\n";
    left_ss << L"Timestamp: " << FormatTimestamp(msg.Timestamp) << L"\r\n";
    left_ss << L"Direction: " << (msg.IsSend ? L"SEND" : L"RECEIVE") << L"\r\n";

    wchar_t processName[32];
    MultiByteToWideChar(CP_ACP, 0, msg.ProcessName, -1, processName, 32);
    left_ss << L"Process: " << processName << L" (PID: " << msg.ProcessId << L")\r\n";
    left_ss << L"Thread ID: " << msg.ThreadId << L"\r\n";
    left_ss << L"Port Handle: " << msg.PortHandle << L"\r\n";
    left_ss << L"Message ID: 0x" << std::hex << msg.MessageId << L"\r\n";
    left_ss << L"Message Type: 0x" << std::hex << msg.MessageType << L"\r\n";
    left_ss << L"Data Length: " << std::dec << msg.DataLength << L" bytes\r\n";
    left_ss << L"Total Length: " << msg.TotalLength << L" bytes\r\n";

    // --- RIGHT COLUMN: Hex dump ---
    if (msg.DataLength > 0) {
        right_ss << L"=== Data Hex Dump ===\r\n\r\n";
        right_ss << FormatHexDump(msg.Data, min(msg.DataLength, sizeof(msg.Data)));
    }

    // --- LEFT COLUMN: Call Stack Display ---
    // If the stack wasn't resolved when the message was captured (Filtering disabled), resolve it now.
    if (!container.StackResolved) {
        UpdateStatusBar(L"Resolving call stack...");
        container.StackInfo = ResolveCombinedStack(msg);
        container.StackResolved = true;
        UpdateStatusBar(L"Ready");
    }

    const auto& stackInfo = container.StackInfo;
    bool hasStack = !stackInfo.KernelStackStrings.empty() || !stackInfo.UserStackStrings.empty();

    if (hasStack) {
        if (stackInfo.UserStackStrings.empty()) {
            left_ss << L"\r\n=== Call Stack (no usermode callstack available) ===\r\n\r\n";
        } else {
            left_ss << L"\r\n=== Call Stack ===\r\n\r\n";
        }

        ULONG frameIndex = 0;

        // Display kernel frames
        if (!stackInfo.KernelStackStrings.empty()) {
            left_ss << L"--- Kernel Mode ---\r\n";
            for (const auto& frameStr : stackInfo.KernelStackStrings) {
                left_ss << std::dec << std::setw(2) << std::setfill(L'0') << frameIndex++ << L" ";
                left_ss << frameStr << L"\r\n";
            }
        }

        // Display usermode frames
        if (!stackInfo.UserStackStrings.empty()) {
            left_ss << L"\r\n--- User Mode ---\r\n";
            for (const auto& frameStr : stackInfo.UserStackStrings) {
                left_ss << std::dec << std::setw(2) << std::setfill(L'0') << frameIndex++ << L" ";
                left_ss << frameStr << L"\r\n";
            }
        }
    }

    // --- Combine the left and right columns side-by-side ---
    std::wstringstream final_ss;

    auto split_lines = [](const std::wstring& str) {
        std::vector<std::wstring> lines;
        std::wistringstream stream(str);
        std::wstring line;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == L'\r') {
                line.pop_back();
            }
            lines.push_back(line);
        }
        return lines;
        };

    std::vector<std::wstring> left_lines = split_lines(left_ss.str());
    std::vector<std::wstring> right_lines = split_lines(right_ss.str());

    const size_t left_col_width = 85;
    const bool hex_dump_exists = msg.DataLength > 0;
    size_t max_lines = max(left_lines.size(), right_lines.size());

    for (size_t i = 0; i < max_lines; ++i) {
        std::wstring current_left = (i < left_lines.size()) ? left_lines[i] : L"";
        std::wstring current_right = (i < right_lines.size()) ? right_lines[i] : L"";

        final_ss << current_left;

        if (hex_dump_exists) {
            if (current_left.length() < left_col_width) {
                final_ss << std::wstring(left_col_width - current_left.length(), L' ');
            }
            final_ss << L" | " << current_right;
        }

        final_ss << L"\r\n";
    }

    SetWindowText(g_hDetailsEdit, final_ss.str().c_str());
}

void ApplyFilter() {
    wchar_t filterText[256];
    GetWindowText(g_hFilterEdit, filterText, 256);
    g_FilterText = filterText;

    g_EnableStackFilter = (SendMessage(g_hStackFilterCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);

    if (g_EnableStackFilter) {
        // Check if any currently stored messages need their stacks resolved
        bool needsResolving = false;
        for (const auto& container : g_Messages) {
            if (!container.StackResolved) {
                needsResolving = true;
                break;
            }
        }

        if (needsResolving) {
            UpdateStatusBar(L"Resolving stacks for all captured messages before filtering... This may take a moment.");
            SendMessage(g_hStatusBar, WM_PAINT, 0, 0);

            for (auto& container : g_Messages) {
                if (!container.StackResolved) {
                    container.StackInfo = ResolveCombinedStack(container.Msg);
                    container.StackResolved = true;
                }
            }
        }
    }

    // Rebuild the ListView with filtered messages
    RebuildListView();

    // Update status bar
    std::wstringstream status;
    if (g_FilterText.empty()) {
        status << L"Filter cleared - showing all " << g_Messages.size() << L" messages";
    }
    else {
        status << L"Filter applied: \"" << g_FilterText << L"\" - showing "
            << g_FilteredIndices.size() << L" of " << g_Messages.size() << L" messages";
    }
    UpdateStatusBar(status.str());
}

void RebuildListView() {
    // Clear the ListView
    SendMessage(g_hListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hListView);

    // Clear filtered indices
    g_FilteredIndices.clear();
    g_FilteredMessages = 0;

    // Re-add all messages that pass the filter
    for (size_t i = 0; i < g_Messages.size(); i++) {
        if (PassesFilter(g_Messages[i], g_FilterText, g_EnableStackFilter)) {
            g_FilteredIndices.push_back(i);
            AddMessageToListView(g_Messages[i].Msg);
            g_FilteredMessages++;
        }
    }

    SendMessage(g_hListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hListView, NULL, FALSE);
}

void UpdateStatusBar(const std::wstring& text) {
    SetWindowText(g_hStatusBar, text.c_str());
}

void FindRpcCallee(int messageIndex) {
    if (messageIndex < 0 || messageIndex >= (int)g_Messages.size()) {
        return;
    }

    g_Messages[messageIndex].RpcState = RpcAnalysisState::AnalysisInProgress;
    ShowMessageDetails(messageIndex);
    UpdateWindow(g_hWnd);

    std::wstring resultString;
    const ALPC_MONITOR_MESSAGE& clientRequestMsg = g_Messages[messageIndex].Msg;

    if (g_hDriver == INVALID_HANDLE_VALUE) {
        resultString = L"Error: Driver not active.";
    }
    else if (!clientRequestMsg.IsSend) {
        resultString = L"Error: Only SEND packets.";
    }
    else if (clientRequestMsg.DataLength < 0x14) {
        resultString = L"Error: Packet is too small.";
    }
    else {
        const ALPC_MONITOR_MESSAGE* pBindMsg = nullptr;
        for (int i = messageIndex; i >= 0; --i) {
            const auto& potentialBind = g_Messages[i].Msg;
            if (potentialBind.ProcessId == clientRequestMsg.ProcessId &&
                potentialBind.PortHandle == clientRequestMsg.PortHandle &&
                potentialBind.IsSend &&
                potentialBind.MessageType == 0x4000) {
                pBindMsg = &potentialBind;
                break;
            }
        }

        if (!pBindMsg) {
            resultString = L"Error: Could not find client's BIND packet. Try monitoring from process startup.";
        }
        else if (pBindMsg->DataLength < 0x43) {
            resultString = L"Error: BIND packet is too small.";
        }
        else {
            UCHAR BindCtxIdentifier[3] = { 0 };
            memcpy(BindCtxIdentifier, pBindMsg->Data + 0x40, 3);

            const ALPC_MONITOR_MESSAGE* pServerBindRecieveMsg = nullptr;
            for (int i = messageIndex; i >= 0; --i) {
                const auto& potentialBind = g_Messages[i].Msg;
                if (!potentialBind.IsSend &&
                    potentialBind.MessageType == 0x6001 &&
                    potentialBind.DataLength >= 0x43 &&
                    memcmp(potentialBind.Data + 0x40, BindCtxIdentifier, sizeof(BindCtxIdentifier)) == 0) {
                    pServerBindRecieveMsg = &potentialBind;
                    break;
                }
            }

            if (!pServerBindRecieveMsg) {
                resultString = L"Error: Could not find server RECV BIND packet.";
            }
            else {
                RPC_CALLEE_INFO_REQUEST request = {};
                request.ServerProcessId = pServerBindRecieveMsg->ProcessId;
                memcpy(&request.InterfaceUuid, pBindMsg->Data + 0xC, sizeof(GUID));
                request.FunctionId = clientRequestMsg.Data[0x14];

                RPC_CALLEE_INFO_RESPONSE calleeInfo = {};
                DWORD bytesReturned = 0;

                if (!DeviceIoControl(g_hDriver, IOCTL_ALPC_FIND_RPC_CALLEE,
                    &request, sizeof(request),
                    &calleeInfo, sizeof(RPC_CALLEE_INFO_RESPONSE),
                    &bytesReturned, NULL) || bytesReturned < sizeof(RPC_CALLEE_INFO_RESPONSE))
                {
                    DWORD error = GetLastError();
                    std::wstringstream ss;
                    ss << L"Driver Error: " << error;
                    resultString = ss.str();
                }
                else {
                    std::wstringstream ss;
                    ss << calleeInfo.ImageName << L"!" << calleeInfo.ModuleName
                        << L" + 0x" << std::hex << std::uppercase << calleeInfo.Offset
                        << L" (Raw: 0x" << std::hex << std::uppercase << calleeInfo.RawAddress << L")";

                    resultString = ss.str();
                }
            }
        }
    }

    g_Messages[messageIndex].RpcAnalysisResult = resultString;
    g_Messages[messageIndex].RpcState = RpcAnalysisState::AnalysisComplete;
    ShowMessageDetails(messageIndex);
}