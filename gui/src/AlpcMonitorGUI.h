#pragma once

#include <windows.h>
#include <vector>
#include "EtwUsermodeStackCapture.h"
#include "AlpcShared.h"

struct ResolvedStackInfo {
    std::vector<std::wstring> KernelStackStrings;
    std::vector<std::wstring> UserStackStrings;
};

enum class RpcAnalysisState {
    NotAnalyzed,
    AnalysisInProgress,
    AnalysisComplete
};

struct MessageContainer {
    ALPC_MONITOR_MESSAGE Msg;
    ResolvedStackInfo StackInfo;
    bool StackResolved = false;
    RpcAnalysisState RpcState = RpcAnalysisState::NotAnalyzed;
    std::wstring RpcAnalysisResult;
};