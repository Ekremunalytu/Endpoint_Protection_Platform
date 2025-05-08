#ifndef DOCKERMANAGER_H
#define DOCKERMANAGER_H

#include <QObject>
#include <QString>
#include <QtCore/QStringList>
#include <QProcess>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include "Interfaces/IDockerManager.h"

// Docker işlemlerinde oluşabilecek hata kodları
enum class DockerErrorCode {
    NoError = 0,
    DockerNotAvailable,
    ContainerNotFound,
    ContainerStartFailed,
    ContainerStopFailed,
    CommandExecutionFailed,
    CopyToContainerFailed,
    CopyFromContainerFailed,
    ImageNotFound,
    ImagePullFailed,
    TimeoutError,
    UnknownError
};

// Docker hata bilgisini saklayan yapı
struct DockerError {
    DockerErrorCode code;
    QString message;
    QString details;
    
    DockerError() : code(DockerErrorCode::NoError), message(""), details("") {}
    DockerError(DockerErrorCode c, const QString& msg, const QString& dtls = "") 
        : code(c), message(msg), details(dtls) {}
    
    bool hasError() const { return code != DockerErrorCode::NoError; }
};

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

    // Arayüze eklenen yeni metodlar - override işaretliyoruz
    bool startContainer(const QString& config) override;
    QString executeCommand(const QString& command) override;
    bool copyFileToContainer(const QString& localPath, const QString& containerPath) override;
    bool stopContainer() override; // Parametre olmadan çağrılabilen versiyon
    bool isContainerRunning() override; // Parametre olmadan çağrılabilen versiyon

    // Arayüzde olmayan ek metodlar 
    bool copyFileFromContainer(const QString& containerPath, const QString& localPath);
    QJsonArray listContainers(bool showAll = false);
    
    // Hata işleme metotları - hem const hem de non-const versiyonları mevcut
    DockerError lastError() const;
    DockerError& lastError();  // Non-const versiyon eklendi
    QString lastErrorMessage() const;
    void clearError() const;  // const olarak güncellendi

private:
    QProcess dockerProcess;
    QString executeDockerCommand(const QStringList& arguments);
    QJsonArray parseDockerOutput(const QString& output, const QString& type);
    
    // Üye değişkenler
    bool containerRunning; 
    QString containerName;
    QString imageName;
    
    // Hata işleme için eklenen değişken - mutable olarak işaretlendi
    mutable DockerError m_lastError;
    
    // Hata ayarlama ve işleme yöntemleri
    void setError(DockerErrorCode code, const QString& message, const QString& details = "") const;
    void logError(const QString& method, const QString& message, const QString& details = "") const;
    void handleException(const QString& method, const std::exception& e) const;
    void handleUnknownException(const QString& method) const;
};

#endif // DOCKERMANAGER_H