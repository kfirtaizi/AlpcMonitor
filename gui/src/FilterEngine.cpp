#include "FilterEngine.h"
#include <algorithm>
#include <vector>
#include <stack>
#include <sstream>

namespace FilterEngine {
    enum class TokenType {
        OPERAND,
        OPERATOR_AND,
        OPERATOR_OR,
        LEFT_PAREN,
        RIGHT_PAREN
    };

    struct Token {
        TokenType type;
        std::wstring value;
    };

    // Helper to get the precedence of an operator. '&&' has higher precedence than '||'.
    int GetPrecedence(TokenType type) {
        if (type == TokenType::OPERATOR_AND) return 2;
        if (type == TokenType::OPERATOR_OR) return 1;
        return 0; // For other tokens
    }

    bool MatchesSinglePattern(const MessageContainer& container,
        const std::wstring& pattern, bool enableStackFilter) {
        if (pattern.empty()) return false;

        std::wstring filterLower = pattern;
        std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::towlower);

        const ALPC_MONITOR_MESSAGE& msg = container.Msg;

        // Check Process Name
        wchar_t processName[32];
        MultiByteToWideChar(CP_ACP, 0, msg.ProcessName, -1, processName, 32);
        std::wstring procLower = processName;
        std::transform(procLower.begin(), procLower.end(), procLower.begin(), ::towlower);
        if (procLower.find(filterLower) != std::wstring::npos) return true;

        // Check PID
        std::wstring pidStr = std::to_wstring(msg.ProcessId);
        if (pidStr.find(filterLower) != std::wstring::npos) return true;

        // Check TID
        std::wstring tidStr = std::to_wstring(msg.ThreadId);
        if (tidStr.find(filterLower) != std::wstring::npos) return true;

        // Check PortHandle
        std::wstring portHandleStr = std::to_wstring(msg.PortHandle);
        if (portHandleStr.find(filterLower) != std::wstring::npos) return true;

        // Check Message Type
        wchar_t typeHexString[32];
        swprintf_s(typeHexString, L"0x%04x", msg.MessageType);
        std::wstring typeStr(typeHexString);
        if (typeStr.find(filterLower) != std::wstring::npos) return true;

        // Check Message ID
        std::wstring messageIdStr = std::to_wstring(msg.MessageId);
        if (messageIdStr.find(filterLower) != std::wstring::npos) return true;

        // Check Direction
        std::wstring direction = msg.IsSend ? L"send" : L"recv";
        if (direction.find(filterLower) != std::wstring::npos) return true;

        // Check Data Length
        std::wstring dataLengthStr = std::to_wstring(msg.DataLength);
        if (dataLengthStr.find(filterLower) != std::wstring::npos) return true;

        // Search in message's data as bytes
        if (filterLower.length() >= 4 && filterLower.length() % 2 == 0) {
            if (std::all_of(filterLower.begin(), filterLower.end(), ::iswxdigit)) {
                std::vector<uint8_t> patternBytes;
                patternBytes.reserve(filterLower.length() / 2);
                bool conversionOk = true;
                for (size_t i = 0; i < filterLower.length(); i += 2) {
                    std::wstring byteString = filterLower.substr(i, 2);
                    wchar_t* end;
                    long value = wcstol(byteString.c_str(), &end, 16);
                    if (*end != 0) {
                        conversionOk = false;
                        break;
                    }
                    patternBytes.push_back(static_cast<uint8_t>(value));
                }

                if (conversionOk && !patternBytes.empty()) {
                    auto it = std::search(
                        msg.Data, msg.Data + msg.DataLength,
                        patternBytes.begin(), patternBytes.end()
                    );
                    if (it != msg.Data + msg.DataLength) {
                        return true;
                    }
                }
            }
        }

        // Search in message's data as ASCII strings
        for (USHORT i = 0; i < msg.DataLength; i++) {
            if (msg.Data[i] >= 32 && msg.Data[i] < 127) {
                USHORT len = 0;
                while (i + len < msg.DataLength && msg.Data[i + len] >= 32 && msg.Data[i + len] < 127) {
                    len++;
                }
                char tempStr[DATA_MAX_LENGTH] = {};
                memcpy(tempStr, &msg.Data[i], min(len, DATA_MAX_LENGTH - 1));
                wchar_t wideStr[DATA_MAX_LENGTH * 2];
                MultiByteToWideChar(CP_ACP, 0, tempStr, -1, wideStr, DATA_MAX_LENGTH * 2);
                std::wstring asciiDataLower = wideStr;
                std::transform(asciiDataLower.begin(), asciiDataLower.end(), asciiDataLower.begin(), ::towlower);
                if (asciiDataLower.find(filterLower) != std::wstring::npos) return true;
                i += len - 1;
            }
        }

        // Search in message's data as Unicode strings
        for (USHORT i = 0; i < msg.DataLength; i += 2) {
            if (i + 1 < msg.DataLength && msg.Data[i + 1] == 0 && msg.Data[i] >= 32 && msg.Data[i] < 127) {
                PWCHAR wstr = (PWCHAR)&msg.Data[i];
                USHORT len = 0;
                while (i + (len * 2) < msg.DataLength && wstr[len] != 0 && wstr[len] >= 32 && wstr[len] < 127) {
                    len++;
                }
                if (len > 0) {
                    std::wstring unicodeDataLower(wstr, len);
                    std::transform(unicodeDataLower.begin(), unicodeDataLower.end(), unicodeDataLower.begin(), ::towlower);
                    if (unicodeDataLower.find(filterLower) != std::wstring::npos) return true;
                    i += len * 2 - 2;
                }
            }
        }

        // If stack filtering is on, check the stack frames
        if (enableStackFilter && container.StackResolved) {
            for (const auto& frame : container.StackInfo.KernelStackStrings) {
                std::wstring frameLower = frame;
                std::transform(frameLower.begin(), frameLower.end(), frameLower.begin(), ::towlower);
                if (frameLower.find(filterLower) != std::wstring::npos) return true;
            }
            for (const auto& frame : container.StackInfo.UserStackStrings) {
                std::wstring frameLower = frame;
                std::transform(frameLower.begin(), frameLower.end(), frameLower.begin(), ::towlower);
                if (frameLower.find(filterLower) != std::wstring::npos) return true;
            }
        }

        return false;
    }
}


bool PassesFilter(const MessageContainer& container, 
    const std::wstring& filterText, bool enableStackFilter) {
    if (filterText.empty()) return true;

    using namespace FilterEngine;

    // Turn the filter string into a sequence of tokens.
    std::vector<Token> tokens;
    std::wstring currentOperand;
    for (size_t i = 0; i < filterText.length(); ++i) {
        wchar_t c = filterText[i];
        if (c == L'&' && i + 1 < filterText.length() && filterText[i + 1] == L'&') {
            if (!currentOperand.empty()) tokens.push_back({ TokenType::OPERAND, currentOperand });
            currentOperand.clear();
            tokens.push_back({ TokenType::OPERATOR_AND });
            i++; // Skip the second '&'
        }
        else if (c == L'|' && i + 1 < filterText.length() && filterText[i + 1] == L'|') {
            if (!currentOperand.empty()) tokens.push_back({ TokenType::OPERAND, currentOperand });
            currentOperand.clear();
            tokens.push_back({ TokenType::OPERATOR_OR });
            i++; // Skip the second '|'
        }
        else if (c == L'(') {
            if (!currentOperand.empty()) tokens.push_back({ TokenType::OPERAND, currentOperand });
            currentOperand.clear();
            tokens.push_back({ TokenType::LEFT_PAREN });
        }
        else if (c == L')') {
            if (!currentOperand.empty()) tokens.push_back({ TokenType::OPERAND, currentOperand });
            currentOperand.clear();
            tokens.push_back({ TokenType::RIGHT_PAREN });
        }
        else if (iswspace(c)) {
            if (!currentOperand.empty()) tokens.push_back({ TokenType::OPERAND, currentOperand });
            currentOperand.clear();
        }
        else {
            currentOperand += c;
        }
    }
    if (!currentOperand.empty()) tokens.push_back({ TokenType::OPERAND, currentOperand });

    if (tokens.empty()) return true;

    // Convert the token sequence into Reverse Polish Notation (RPN) for easy evaluation.
    std::vector<Token> postfix;
    std::stack<Token> opStack;

    for (const auto& token : tokens) {
        switch (token.type) {
        case TokenType::OPERAND:
            postfix.push_back(token);
            break;
        case TokenType::OPERATOR_AND:
        case TokenType::OPERATOR_OR:
            while (!opStack.empty() && opStack.top().type != TokenType::LEFT_PAREN &&
                GetPrecedence(opStack.top().type) >= GetPrecedence(token.type)) {
                postfix.push_back(opStack.top());
                opStack.pop();
            }
            opStack.push(token);
            break;
        case TokenType::LEFT_PAREN:
            opStack.push(token);
            break;
        case TokenType::RIGHT_PAREN:
            while (!opStack.empty() && opStack.top().type != TokenType::LEFT_PAREN) {
                postfix.push_back(opStack.top());
                opStack.pop();
            }
            if (opStack.empty()) return false; // Mismatched parentheses error
            opStack.pop(); // Pop the left parenthesis
            break;
        }
    }

    while (!opStack.empty()) {
        if (opStack.top().type == TokenType::LEFT_PAREN) return false; // Mismatched parentheses
        postfix.push_back(opStack.top());
        opStack.pop();
    }

    // Evaluate the RPN expression to get the final boolean result.
    std::stack<bool> evalStack;

    for (const auto& token : postfix) {
        if (token.type == TokenType::OPERAND) {
            evalStack.push(MatchesSinglePattern(container, token.value, enableStackFilter));
        }
        else if (token.type == TokenType::OPERATOR_AND || token.type == TokenType::OPERATOR_OR) {
            if (evalStack.size() < 2) return false; // Syntax error

            bool val2 = evalStack.top(); evalStack.pop();
            bool val1 = evalStack.top(); evalStack.pop();

            if (token.type == TokenType::OPERATOR_AND) {
                evalStack.push(val1 && val2);
            }
            else { // OPERATOR_OR
                evalStack.push(val1 || val2);
            }
        }
    }

    if (evalStack.size() != 1) return false; // Malformed expression

    return evalStack.top();
}