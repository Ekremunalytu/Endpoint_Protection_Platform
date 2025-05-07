//
// Created by Ekrem Ünal on 21.04.2025.
//

#ifndef YARARULEMANAGER_H
#define YARARULEMANAGER_H

#include <string>
#include <vector>
#include <system_error>
#include <functional>
#include <memory>
#include "Interfaces/IYaraRuleManager.h"

// Forward declarations - using typedef instead of forward struct declarations to avoid conflicts
struct YR_RULES;
// Note: Not forward-declaring YR_COMPILER as it's defined in yara.h

// Error codes for YARA operations
enum class YaraErrorCodes {
    success = 0,
    AlreadyInitialized,
    NotInitialized,
    InternalError,
    FileNotFound,
    CompilerError,
    RulesNotCompiled,
    ScanError
};

// Custom error category for YARA
namespace std {
    template<>
    struct is_error_code_enum<YaraErrorCodes> : true_type {};
}

std::error_code make_error_code(YaraErrorCodes e);

class YaraRuleManager : public IYaraRuleManager {
private:
    YR_RULES* rules;
    void* compiler; // Using void* to avoid forward declaration issues
    bool initialized = false;
    std::function<void(const std::string&)> callback;

public:
    YaraRuleManager();
    ~YaraRuleManager() override;

    // IYaraRuleManager interface methods - without noexcept to match interface
    std::error_code initialize() override;
    std::error_code loadRules(const std::string& rulesPath) override;
    std::error_code scanFile(const std::string& filePath, std::vector<std::string>& matches) override;
    
    // Additional methods used in implementation
    std::error_code finalize();
    std::error_code unloadRules();
    std::error_code compileRules();
    std::error_code scanMemory(const uint8_t* data, size_t size, std::vector<std::string>& matches);
    
    // Callback handling
    void setCallback(std::function<void(const std::string&)> cb);
    std::function<void(const std::string&)> getCallback() const { return callback; }
};

#endif // YARARULEMANAGER_H