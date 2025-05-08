#include "../Headers/ServiceLocator.h"
#include "../../Scanning/Headers/ScanManager.h"
#include <memory>

// Static üyelerin tanımlanması - shared_ptr ile
std::shared_ptr<IApiManager> ServiceLocator::apiManager = nullptr;
std::shared_ptr<IYaraRuleManager> ServiceLocator::yaraRuleManager = nullptr;
std::shared_ptr<ICdrManager> ServiceLocator::cdrManager = nullptr;
std::shared_ptr<ISandboxManager> ServiceLocator::sandboxManager = nullptr;
std::shared_ptr<IDbManager> ServiceLocator::dbManager = nullptr;
std::shared_ptr<IDockerManager> ServiceLocator::dockerManager = nullptr;
std::shared_ptr<ScanManager> ServiceLocator::scanManager = nullptr;

// ScanManager için method implementasyonları
void ServiceLocator::provide(std::shared_ptr<ScanManager> service) {
    scanManager = service;
}

void ServiceLocator::provide(ScanManager* service) {
    scanManager = std::shared_ptr<ScanManager>(service);
}

std::shared_ptr<ScanManager> ServiceLocator::getScanManagerPtr() {
    return scanManager;
}

ScanManager* ServiceLocator::getScanManager() {
    return scanManager.get();
}