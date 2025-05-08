#ifndef IDOCKERMANAGER_H
#define IDOCKERMANAGER_H

#include <QString>
#include <QStringList>
#include <QtCore/QJsonArray>
#include <QJsonObject>

class IDockerManager {
public:
    virtual ~IDockerManager() = default;
    
    virtual bool isDockerAvailable() const = 0;
    virtual QJsonArray getDockerContainers() = 0;
    virtual QJsonArray getDockerImages() = 0;
    virtual bool runContainer(const QString& imageName, const QString& containerName, const QStringList& params) = 0;
    virtual bool stopContainer(const QString& containerName) = 0;
    virtual bool isContainerRunning(const QString& containerName) = 0;
    virtual QString getContainerLogs(const QString& containerName) = 0;
    
    virtual bool startContainer(const QString& containerConfig) = 0;
    virtual bool copyFileToContainer(const QString& localPath, const QString& containerPath) = 0;
    virtual QString executeCommand(const QString& command) = 0;
    virtual bool stopContainer() = 0;
    virtual bool isContainerRunning() = 0;
};

#endif // IDOCKERMANAGER_H