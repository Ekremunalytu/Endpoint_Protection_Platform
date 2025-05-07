#ifndef DOCKERMANAGER_H
#define DOCKERMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QProcess>
#include <QJsonArray>
#include <QJsonObject>
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

private:
    QProcess dockerProcess;
    QString executeDockerCommand(const QStringList& arguments);
    QJsonArray parseDockerOutput(const QString& output, const QString& type);
};

#endif // DOCKERMANAGER_H