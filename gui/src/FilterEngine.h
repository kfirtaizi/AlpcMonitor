#pragma once

#include "AlpcMonitorGUI.h"
#include <string>

bool PassesFilter(
    const MessageContainer& container,
    const std::wstring& filterText,
    bool enableStackFilter
);