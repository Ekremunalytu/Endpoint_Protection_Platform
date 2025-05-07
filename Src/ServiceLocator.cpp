#include "../Headers/ServiceLocator.h"

// Static üyelerin tanımlanması
IApiManager* ServiceLocator::apiManager = nullptr;
IYaraRuleManager* ServiceLocator::yaraRuleManager = nullptr;
ICdrManager* ServiceLocator::cdrManager = nullptr;
ISandboxManager* ServiceLocator::sandboxManager = nullptr;
IDbManager* ServiceLocator::dbManager = nullptr;
IDockerManager* ServiceLocator::dockerManager = nullptr;