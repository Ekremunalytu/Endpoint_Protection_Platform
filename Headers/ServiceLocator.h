#ifndef SERVICELOCATOR_H
#define SERVICELOCATOR_H

#include "Interfaces/IApiManager.h"
#include "Interfaces/IYaraRuleManager.h"
#include "Interfaces/ICdrManager.h"
#include "Interfaces/ISandboxManager.h"
#include "Interfaces/IDbManager.h"
#include "Interfaces/IDockerManager.h"
#include <memory>

class ServiceLocator {
private:
    static std::shared_ptr<IApiManager> apiManager;
    static std::shared_ptr<IYaraRuleManager> yaraRuleManager;
    static std::shared_ptr<ICdrManager> cdrManager;
    static std::shared_ptr<ISandboxManager> sandboxManager;
    static std::shared_ptr<IDbManager> dbManager;
    static std::shared_ptr<IDockerManager> dockerManager;

public:
    // Smart pointer tabanlı hizmet sağlayıcılar
    static void provide(std::shared_ptr<IApiManager> service) { apiManager = service; }
    static void provide(std::shared_ptr<IYaraRuleManager> service) { yaraRuleManager = service; }
    static void provide(std::shared_ptr<ICdrManager> service) { cdrManager = service; }
    static void provide(std::shared_ptr<ISandboxManager> service) { sandboxManager = service; }
    static void provide(std::shared_ptr<IDbManager> service) { dbManager = service; }
    static void provide(std::shared_ptr<IDockerManager> service) { dockerManager = service; }

    // Raw pointer kullanımını destekleyen eski fonksiyonlar (geriye dönük uyumluluk için)
    static void provide(IApiManager* service) { apiManager = std::shared_ptr<IApiManager>(service); }
    static void provide(IYaraRuleManager* service) { yaraRuleManager = std::shared_ptr<IYaraRuleManager>(service); }
    static void provide(ICdrManager* service) { cdrManager = std::shared_ptr<ICdrManager>(service); }
    static void provide(ISandboxManager* service) { sandboxManager = std::shared_ptr<ISandboxManager>(service); }
    static void provide(IDbManager* service) { dbManager = std::shared_ptr<IDbManager>(service); }
    static void provide(IDockerManager* service) { dockerManager = std::shared_ptr<IDockerManager>(service); }

    // Smart pointer döndüren getterlar
    static std::shared_ptr<IApiManager> getApiManagerPtr() { return apiManager; }
    static std::shared_ptr<IYaraRuleManager> getYaraRuleManagerPtr() { return yaraRuleManager; }
    static std::shared_ptr<ICdrManager> getCdrManagerPtr() { return cdrManager; }
    static std::shared_ptr<ISandboxManager> getSandboxManagerPtr() { return sandboxManager; }
    static std::shared_ptr<IDbManager> getDbManagerPtr() { return dbManager; }
    static std::shared_ptr<IDockerManager> getDockerManagerPtr() { return dockerManager; }

    // Geriye dönük uyumluluğu korumak için raw pointer döndüren getterlar
    static IApiManager* getApiManager() { return apiManager.get(); }
    static IYaraRuleManager* getYaraRuleManager() { return yaraRuleManager.get(); }
    static ICdrManager* getCdrManager() { return cdrManager.get(); }
    static ISandboxManager* getSandboxManager() { return sandboxManager.get(); }
    static IDbManager* getDbManager() { return dbManager.get(); }
    static IDockerManager* getDockerManager() { return dockerManager.get(); }
};

#endif // SERVICELOCATOR_H