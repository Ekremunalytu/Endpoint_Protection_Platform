#ifndef SANDBOXMANAGER_H
#define SANDBOXMANAGER_H

#include <QString>
#include <QStringList>
#include <QJsonObject>
#include "DockerManager.h"

class SandboxManager : public QObject {
    Q_OBJECT

public:
    SandboxManager(QObject *parent = nullptr);
    ~SandboxManager();

    bool initialize();
    QJsonObject analyzeFile(const QString& filePath);
    QJsonObject getAnalysisResults();
    QJsonObject parseFileSystemActivity();
    
    // Yeni eklenen metotlar
    void setSandboxImageName(const QString& imageName);
    QString getCurrentImageName() const;
    QStringList getAvailableSandboxImages() const;

private:
    DockerManager *dockerManager;
    QString sandboxImageName;
    int analysisTimeout;
    QStringList monitoredBehaviors;
    QString resultsDir;
    
    QJsonObject parseNetworkActivity();
    QJsonObject parseProcessActivity();
    QJsonObject parseRegistryActivity();
};

#endif // SANDBOXMANAGER_H