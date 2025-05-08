#include "../Headers/ServiceLocator.h"
#include <memory>

// Static üyelerin tanımlanması - shared_ptr ile
std::shared_ptr<IApiManager> ServiceLocator::apiManager = nullptr;
std::shared_ptr<IYaraRuleManager> ServiceLocator::yaraRuleManager = nullptr;
std::shared_ptr<ICdrManager> ServiceLocator::cdrManager = nullptr;
std::shared_ptr<ISandboxManager> ServiceLocator::sandboxManager = nullptr;
std::shared_ptr<IDbManager> ServiceLocator::dbManager = nullptr;
std::shared_ptr<IDockerManager> ServiceLocator::dockerManager = nullptr;