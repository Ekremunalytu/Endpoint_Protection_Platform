#ifndef SANDBOXMANAGER_H
#define SANDBOXMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include "Interfaces/ISandboxManager.h"
#include "DockerManager.h"

class SandboxManager : public QObject, public ISandboxManager {
    Q_OBJECT

public:
    SandboxManager(QObject *parent = nullptr);
    ~SandboxManager();

    // ISandboxManager arayüzünü uygulama
    bool initialize() override;
    QJsonObject analyzeFile(const QString& filePath) override;
    QJsonObject getAnalysisResults() override;
    void setSandboxImageName(const QString& imageName) override;
    QString getCurrentImageName() const override;
    QStringList getAvailableSandboxImages() const override;

private:
    DockerManager *dockerManager;
    QString sandboxImageName;
    int analysisTimeout;
    QStringList monitoredBehaviors;
    QString resultsDir;
    
    // Yardımcı metotlar
    QJsonObject parseFileSystemActivity();
    QJsonObject parseNetworkActivity();
    QJsonObject parseProcessActivity();
    QJsonObject parseRegistryActivity();
};

#endif // SANDBOXMANAGER_H