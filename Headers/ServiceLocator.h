#ifndef SERVICELOCATOR_H
#define SERVICELOCATOR_H

#include "Interfaces/IApiManager.h"
#include "Interfaces/IYaraRuleManager.h"
#include "Interfaces/ICdrManager.h"
#include "Interfaces/ISandboxManager.h"
#include "Interfaces/IDbManager.h"
#include "Interfaces/IDockerManager.h"

class ServiceLocator {
private:
    static IApiManager* apiManager;
    static IYaraRuleManager* yaraRuleManager;
    static ICdrManager* cdrManager;
    static ISandboxManager* sandboxManager;
    static IDbManager* dbManager;
    static IDockerManager* dockerManager;

public:
    static void provide(IApiManager* service) { apiManager = service; }
    static void provide(IYaraRuleManager* service) { yaraRuleManager = service; }
    static void provide(ICdrManager* service) { cdrManager = service; }
    static void provide(ISandboxManager* service) { sandboxManager = service; }
    static void provide(IDbManager* service) { dbManager = service; }
    static void provide(IDockerManager* service) { dockerManager = service; }

    static IApiManager* getApiManager() { return apiManager; }
    static IYaraRuleManager* getYaraRuleManager() { return yaraRuleManager; }
    static ICdrManager* getCdrManager() { return cdrManager; }
    static ISandboxManager* getSandboxManager() { return sandboxManager; }
    static IDbManager* getDbManager() { return dbManager; }
    static IDockerManager* getDockerManager() { return dockerManager; }
};

#endif // SERVICELOCATOR_H