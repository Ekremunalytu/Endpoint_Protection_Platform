#ifndef DOCKERMANAGER_H
#define DOCKERMANAGER_H

#include <QObject>
#include <QProcess>
#include <QString>
#include <QDebug>
#include <QJsonObject>
#include <QJsonArray>

class DockerManager : public QObject {
    Q_OBJECT

public:
    DockerManager(QObject *parent = nullptr);
    ~DockerManager();

    bool isDockerAvailable();
    bool startContainer(const QString& config);
    void stopContainer();
    bool isContainerRunning();
    QString executeCommand(const QString& command);
    bool copyFileToContainer(const QString& localPath, const QString& containerPath);
    bool copyFileFromContainer(const QString& containerPath, const QString& localPath);

    QJsonArray listContainers(bool showAll = true);

private:
    QProcess *dockerProcess;
    QString containerName;
    QString imageName;
    bool containerRunning;
};

#endif // DOCKERMANAGER_H