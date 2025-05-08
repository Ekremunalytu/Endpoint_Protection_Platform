#ifndef IYARARULEMANAGER_H
#define IYARARULEMANAGER_H

#include <string>
#include <vector>
#include <system_error>

// YARA tarama servislerini kullanmak için soyut arayüz
class IYaraRuleManager {
public:
    virtual ~IYaraRuleManager() = default;
    
    virtual std::error_code initialize() = 0;
    virtual std::error_code loadRules(const std::string& rulesPath) = 0;
    virtual std::error_code scanFile(const std::string& filePath, std::vector<std::string>& matches) = 0;
};

#endif // IYARARULEMANAGER_H