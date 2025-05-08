#ifndef SANDBOXMANAGER_H
#define SANDBOXMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include <memory>
#include "ISandboxManager.h"
#include "IDockerManager.h" // Changed from Interfaces/Headers/IDockerManager.h

// İleri bildirimler - header bağımlılıklarını azaltmak için
class DockerManager;

class SandboxManager : public QObject, public ISandboxManager {
    Q_OBJECT

public:
    // Constructor - dependency injection destekli
    explicit SandboxManager(QObject *parent = nullptr);
    
    // Docker Manager enjeksiyonu için alternatif constructor
    explicit SandboxManager(std::shared_ptr<IDockerManager> dockerMgr, QObject *parent = nullptr);
    
    // Destructor
    ~SandboxManager() override;

    // ISandboxManager arayüzünü uygulama
    bool initialize() override;
    QJsonObject analyzeFile(const QString& filePath) override;
    QJsonObject getAnalysisResults() override;
    void setSandboxImageName(const QString& imageName) override;
    QString getCurrentImageName() const override;
    QStringList getAvailableSandboxImages() const override;

private:
    // Docker yöneticisini smart pointer ile tutuyoruz ve interface üzerinden kullanıyoruz
    std::shared_ptr<IDockerManager> dockerManager;
    
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