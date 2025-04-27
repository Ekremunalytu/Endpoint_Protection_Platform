#include "Headers/YaraRuleManager.h"
#include <fstream>
#include <cstdio>
#include <iostream>
#include <memory>

extern "C" {
    #include <yara.h>
}

// Static callback fonksiyonu
static int yara_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    auto* manager = reinterpret_cast<YaraRuleManager*>(user_data);
    // CALLBACK_MSG_RULE_MATCHING, YARA eşleşme mesajı
    if (message == CALLBACK_MSG_RULE_MATCHING && manager && manager->getCallback()) {
        YR_RULE* rule = static_cast<YR_RULE*>(message_data);
        manager->getCallback()(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// Constructor & Destructor
YaraRuleManager::YaraRuleManager() = default;

YaraRuleManager::~YaraRuleManager() {
    finalize();
}

// Initialize / Finalize
std::error_code YaraRuleManager::initialize() noexcept {
    if (initialized)
        return make_error_code(YaraErrorCodes::AlreadyInitialized);

    int result = yr_initialize();
    if (result != ERROR_SUCCESS)
        return make_error_code(YaraErrorCodes::InternalError);

    initialized = true;
    return make_error_code(YaraErrorCodes::success);
}

std::error_code YaraRuleManager::finalize() noexcept {
    if (!initialized)
        return make_error_code(YaraErrorCodes::NotInitialized);

    unloadRules();
    yr_finalize();
    initialized = false;
    return make_error_code(YaraErrorCodes::success);
}

// Load & Unload Rules
std::error_code YaraRuleManager::loadRules(const std::string& rulesFilePath) noexcept {
    if (!initialized)
        return make_error_code(YaraErrorCodes::NotInitialized);

    unloadRules();

    std::ifstream ifs(rulesFilePath);
    if (!ifs.is_open())
        return make_error_code(YaraErrorCodes::FileNotFound);
    ifs.close();

    YR_COMPILER* rawCompiler = nullptr;
    int cres = yr_compiler_create(&rawCompiler);
    if (cres != ERROR_SUCCESS)
        return make_error_code(YaraErrorCodes::InternalError);
    compiler.reset(rawCompiler);

    FILE* ruleFile = fopen(rulesFilePath.c_str(), "r");
    if (!ruleFile)
        return make_error_code(YaraErrorCodes::FileNotFound);

    cres = yr_compiler_add_file(
        compiler.get(),
        ruleFile,
        nullptr,
        rulesFilePath.c_str()
    );
    fclose(ruleFile);
    if (cres != ERROR_SUCCESS)
        return make_error_code(YaraErrorCodes::CompilerError);

    return make_error_code(YaraErrorCodes::success);
}

std::error_code YaraRuleManager::unloadRules() noexcept {
    compiler.reset();
    rules.reset();
    return make_error_code(YaraErrorCodes::success);
}

// Compile Rules
std::error_code YaraRuleManager::compileRules() noexcept {
    if (!compiler)
        return make_error_code(YaraErrorCodes::RulesNotCompiled);

    YR_RULES* rawRules = nullptr;
    int cres = yr_compiler_get_rules(compiler.get(), &rawRules);
    if (cres != ERROR_SUCCESS)
        return make_error_code(YaraErrorCodes::CompilerError);

    rules.reset(rawRules);
    compiler.reset();
    return make_error_code(YaraErrorCodes::success);
}

// Callback setter
void YaraRuleManager::setCallback(std::function<void(const std::string&)> cb) noexcept {
    callback = std::move(cb);
}

// Scanning Methods
std::error_code YaraRuleManager::scanFile(const std::string& filePath, std::vector<std::string>& matches) noexcept {
    if (!initialized)
        return make_error_code(YaraErrorCodes::NotInitialized);
    if (!rules)
        return make_error_code(YaraErrorCodes::RulesNotCompiled);

    matches.clear();
    setCallback([&matches](const std::string& name) { matches.push_back(name); });

    int sres = yr_rules_scan_file(
        rules.get(),
        filePath.c_str(),
        0,
        yara_callback,
        this,
        0
    );
    if (sres != ERROR_SUCCESS)
        return make_error_code(YaraErrorCodes::ScanError);

    return make_error_code(YaraErrorCodes::success);
}

std::error_code YaraRuleManager::scanMemory(const uint8_t* data, size_t size, std::vector<std::string>& matches) noexcept {
    if (!initialized)
        return make_error_code(YaraErrorCodes::NotInitialized);
    if (!rules)
        return make_error_code(YaraErrorCodes::RulesNotCompiled);

    matches.clear();
    setCallback([&matches](const std::string& name) { matches.push_back(name); });

    int sres = yr_rules_scan_mem(
        rules.get(),
        data,
        size,
        0,
        yara_callback,
        this,
        0
    );
    if (sres != ERROR_SUCCESS)
        return make_error_code(YaraErrorCodes::ScanError);

    return make_error_code(YaraErrorCodes::success);
}
