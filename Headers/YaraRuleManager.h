//
// Created by Ekrem Ünal on 21.04.2025.
//

#ifndef YARARULEMANAGER_H
#define YARARULEMANAGER_H


#include <yara.h>
#include <string>
#include <vector>
#include <functional>
#include <system_error>
#include <memory> // std::unique_ptr için bu başlık dosyası gerekli

// burada hata kodları tanımanmıştır.
enum class  YaraErrorCodes {
    success = 0,
    NotInitialized,
    AlreadyInitialized,
    FileNotFound,
    CompilerError,
    RulesNotCompiled,
    ScanError,
    CallbackNotSet,
    InternalError,

};

class YaraErrorCategory : public std::error_category {
    const char* name() const noexcept override {
        return "YaraErrorCodes";
    }
    std::string message(int ev) const override {
        switch (static_cast<YaraErrorCodes>(ev)) {
            case YaraErrorCodes::success: return "success";
            case YaraErrorCodes::NotInitialized: return "Rule Not initialized";
            case YaraErrorCodes::AlreadyInitialized: return "Rule has already been initalized";
            case YaraErrorCodes::FileNotFound: return "File not found";
            case YaraErrorCodes::CompilerError: return "Compiler Error";
            case YaraErrorCodes::RulesNotCompiled: return "Rules not compiled";
            case YaraErrorCodes::ScanError: return "Scan error";
            default: return "Unknown error";
        }
    }
};


inline const std::error_category& YaraErrorCodesCategory() {
    static YaraErrorCategory instance;
    return instance;
};

inline std::error_code make_error_code(YaraErrorCodes e) {
    return { static_cast<int>(e), YaraErrorCodesCategory() };
};

namespace std {
    template<> struct is_error_code_enum<YaraErrorCategory> : true_type {};
}


class YaraRuleManager {
public:
    YaraRuleManager();
    ~YaraRuleManager();

    YaraRuleManager(const YaraRuleManager&) = delete;
    YaraRuleManager& operator=(const YaraRuleManager&) = delete;

    YaraRuleManager(YaraRuleManager&&) noexcept = delete;
    YaraRuleManager& operator=(YaraRuleManager&&) noexcept = delete;

    std::error_code initialize() noexcept;
    std::error_code finalize() noexcept;

    std::error_code loadRules(const std::string& rulesFilePath) noexcept;
    std::error_code unloadRules() noexcept;
    std::error_code compileRules() noexcept;

    std::error_code scanFile(const std::string& filePath, std::vector<std::string>& matches) noexcept;
    std::error_code scanMemory(const uint8_t* data, size_t size, std::vector<std::string>& matches) noexcept;
    void setCallback(std::function<void(const std::string&)> callback) noexcept;
    // Callback'a erişim için getter
    std::function<void(const std::string&)>& getCallback() { return callback; }

private:
    bool initialized = false;

    struct compilerDeleter {void operator()(YR_COMPILER* p) const noexcept { if (p) yr_compiler_destroy(p);}};
    struct rulesDeleter {void operator()(YR_RULES* p) const noexcept { if (p) yr_rules_destroy(p);}};

    std::unique_ptr<YR_COMPILER, compilerDeleter> compiler;
    std::unique_ptr<YR_RULES, rulesDeleter> rules;

    std::function<void(const std::string&)> callback;


};


#endif //YARARULEMANAGER_H