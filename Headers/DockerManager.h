#ifndef DOCKERMANAGER_H
#define DOCKERMANAGER_H

#include <QObject>
#include <QString>
#include <QtCore/QStringList>
#include <QProcess>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include "Interfaces/IDockerManager.h"

class DockerManager : public QObject, public IDockerManager {
    Q_OBJECT

public:
    DockerManager(QObject *parent = nullptr);
    ~DockerManager();

    // IDockerManager interface implementation
    bool isDockerAvailable() const override;
    QJsonArray getDockerContainers() override;
    QJsonArray getDockerImages() override;
    bool runContainer(const QString& imageName, const QString& containerName, const QStringList& params) override;
    bool stopContainer(const QString& containerName) override;
    bool isContainerRunning(const QString& containerName) override;
    QString getContainerLogs(const QString& containerName) override;

    // Additional methods
    bool startContainer(const QString& config);
    QString executeCommand(const QString& command);
    bool copyFileToContainer(const QString& localPath, const QString& containerPath);
    bool copyFileFromContainer(const QString& containerPath, const QString& localPath);
    QJsonArray listContainers(bool showAll = false);
    bool isContainerRunning(); // Overloaded version for internal use
    void stopContainer(); // Overloaded version for internal use

private:
    QProcess dockerProcess;
    QString executeDockerCommand(const QStringList& arguments);
    QJsonArray parseDockerOutput(const QString& output, const QString& type);
    
    // Added missing member variables
    bool containerRunning; 
    QString containerName;
    QString imageName;
};

#endif // DOCKERMANAGER_H