#ifndef ISANDBOXMANAGER_H
#define ISANDBOXMANAGER_H

#include <QString>
#include <QStringList>
#include <QJsonObject>

// Sandbox analiz servisini kullanmak için soyut arayüz
class ISandboxManager {
public:
    virtual ~ISandboxManager() = default;
    
    virtual bool initialize() = 0;
    virtual QJsonObject analyzeFile(const QString& filePath) = 0;
    virtual QJsonObject getAnalysisResults() = 0;
    virtual void setSandboxImageName(const QString& imageName) = 0;
    virtual QString getCurrentImageName() const = 0;
    virtual QStringList getAvailableSandboxImages() const = 0;
};

#endif // ISANDBOXMANAGER_H