#include "../Headers/DockerManager.h"
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QJsonArray>
#include <QJsonObject>

DockerManager::DockerManager(QObject *parent) : QObject(parent), dockerProcess(new QProcess(this)), containerRunning(false) {
    // Docker process ayarları
    dockerProcess->setProcessChannelMode(QProcess::MergedChannels);
}

DockerManager::~DockerManager() {
    if (isContainerRunning()) {
        stopContainer();
    }
    delete dockerProcess;
}

bool DockerManager::isDockerAvailable() {
    dockerProcess->start("docker", QStringList() << "--version");
    dockerProcess->waitForFinished();
    
    if (dockerProcess->exitCode() != 0) {
        qDebug() << "Docker is not available: " << dockerProcess->readAllStandardOutput();
        return false;
    }
    
    qDebug() << "Docker is available: " << dockerProcess->readAllStandardOutput();
    return true;
}

bool DockerManager::startContainer(const QString& config) {
    if (!isDockerAvailable()) {
        qDebug() << "Docker is not available, cannot start container";
        return false;
    }

    // Konfigürasyon parametresini ayrıştır
    // Beklenen format: "name=container_name,image=image_name"
    QString name = "";
    QString image = "";
    
    QStringList parts = config.split(',');
    for (const QString& part : parts) {
        QStringList keyValue = part.split('=');
        if (keyValue.size() == 2) {
            if (keyValue[0].trimmed() == "name") {
                name = keyValue[1].trimmed();
            } else if (keyValue[0].trimmed() == "image") {
                image = keyValue[1].trimmed();
            }
        }
    }
    
    // Gerekli parametreler var mı kontrol et
    if (name.isEmpty() || image.isEmpty()) {
        qDebug() << "Container name or image not specified in config:" << config;
        return false;
    }
    
    // Container adını ve imajını kaydet
    containerName = name;
    imageName = image;
    
    qDebug() << "Starting container with name:" << containerName << "and image:" << imageName;
    
    // Önce mevcut bir konteyner varsa kaldır
    if (isContainerRunning()) {
        qDebug() << "Container is already running, stopping it first";
        stopContainer();
    }
    
    // Konteyner imajını çek
    qDebug() << "Pulling image:" << imageName;
    dockerProcess->start("docker", QStringList() << "pull" << imageName);
    dockerProcess->waitForFinished(30000);  // 30 saniye bekle
    
    if (dockerProcess->exitCode() != 0) {
        qDebug() << "Failed to pull image:" << imageName;
        qDebug() << "Error:" << dockerProcess->readAllStandardError();
        // İmaj çekemesek bile mevcut imajla devam etmeyi deneyelim
    }
    
    // Örnek bir container başlatma:
    qDebug() << "Starting container with name:" << containerName << "using image:" << imageName;
    
    // Bazı temel dizinleri bağlayalım
    QStringList runArgs;
    runArgs << "run" << "-d" << "--name" << containerName;
    
    // Geçici bir dizin oluştur ve bağla
    QString tempDir = QDir::tempPath() + "/" + containerName;
    QDir().mkpath(tempDir + "/input");
    QDir().mkpath(tempDir + "/output");
    
    runArgs << "-v" << tempDir + "/input:/input";
    runArgs << "-v" << tempDir + "/output:/output";
    runArgs << imageName;
    
    dockerProcess->start("docker", runArgs);
    dockerProcess->waitForFinished(30000);  // 30 saniye bekle
    
    if (dockerProcess->exitCode() != 0) {
        qDebug() << "Failed to start container: " << dockerProcess->readAllStandardError();
        return false;
    }
    
    containerRunning = true;
    qDebug() << "Container started successfully: " << containerName;
    return true;
}

void DockerManager::stopContainer() {
    if (!containerRunning) {
        qDebug() << "Container is not running";
        return;
    }
    
    dockerProcess->start("docker", QStringList() << "stop" << containerName);
    dockerProcess->waitForFinished();
    
    dockerProcess->start("docker", QStringList() << "rm" << containerName);
    dockerProcess->waitForFinished();
    
    containerRunning = false;
    qDebug() << "Container stopped and removed: " << containerName;
}

bool DockerManager::isContainerRunning() {
    dockerProcess->start("docker", QStringList() << "ps" << "-q" << "-f" << "name=" + containerName);
    dockerProcess->waitForFinished();
    
    QString output = dockerProcess->readAllStandardOutput().trimmed();
    containerRunning = !output.isEmpty();
    return containerRunning;
}

QString DockerManager::executeCommand(const QString& command) {
    if (!isContainerRunning()) {
        qDebug() << "Container is not running, cannot execute command";
        return QString();
    }
    
    dockerProcess->start("docker", QStringList() << "exec" << containerName << "sh" << "-c" << command);
    dockerProcess->waitForFinished();
    
    if (dockerProcess->exitCode() != 0) {
        qDebug() << "Failed to execute command in container: " << dockerProcess->readAllStandardError();
        return QString();
    }
    
    return dockerProcess->readAllStandardOutput().trimmed();
}

bool DockerManager::copyFileToContainer(const QString& localPath, const QString& containerPath) {
    if (!isContainerRunning()) {
        qDebug() << "Container is not running, cannot copy file";
        return false;
    }
    
    QFileInfo fileInfo(localPath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        qDebug() << "Local file does not exist: " << localPath;
        return false;
    }
    
    dockerProcess->start("docker", QStringList() << "cp" << localPath << containerName + ":" + containerPath);
    dockerProcess->waitForFinished();
    
    if (dockerProcess->exitCode() != 0) {
        qDebug() << "Failed to copy file to container: " << dockerProcess->readAllStandardError();
        return false;
    }
    
    qDebug() << "File copied to container successfully";
    return true;
}

bool DockerManager::copyFileFromContainer(const QString& containerPath, const QString& localPath) {
    if (!isContainerRunning()) {
        qDebug() << "Container is not running, cannot copy file";
        return false;
    }
    
    // Yerel dizinin var olduğundan emin olalım
    QFileInfo dirInfo(QFileInfo(localPath).absolutePath());
    if (!dirInfo.exists() || !dirInfo.isDir()) {
        QDir().mkpath(dirInfo.absolutePath());
    }
    
    dockerProcess->start("docker", QStringList() << "cp" << containerName + ":" + containerPath << localPath);
    dockerProcess->waitForFinished();
    
    if (dockerProcess->exitCode() != 0) {
        qDebug() << "Failed to copy file from container: " << dockerProcess->readAllStandardError();
        return false;
    }
    
    qDebug() << "File copied from container successfully";
    return true;
}

QJsonArray DockerManager::listContainers(bool showAll) {
    QJsonArray containerList;
    
    // Docker komutunu oluştur
    QStringList args;
    args << "ps";
    if (showAll) {
        args << "-a";  // Tüm konteynerleri göster (durmuş olanlar dahil)
    }
    args << "--format" << "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}";
    
    // Komutu çalıştır
    dockerProcess->start("docker", args);
    dockerProcess->waitForFinished();
    
    // Sonucu analiz et
    if (dockerProcess->exitCode() != 0) {
        qDebug() << "Docker container listesi alınamadı:" << dockerProcess->readAllStandardError();
        return containerList;
    }
    
    QString output = dockerProcess->readAllStandardOutput().trimmed();
    QStringList containers = output.split("\n");
    
    // Her konteyneri JSON objesine dönüştür
    for (const QString& container : containers) {
        if (container.trimmed().isEmpty()) continue;
        
        QStringList parts = container.split("\t");
        QJsonObject containerObj;
        
        if (parts.size() >= 5) {
            containerObj["id"] = parts[0];
            containerObj["name"] = parts[1];
            containerObj["image"] = parts[2];
            containerObj["status"] = parts[3];
            containerObj["ports"] = parts[4];
            containerObj["current"] = (parts[1] == containerName);  // Mevcut container mı?
        }
        else if (parts.size() >= 4) {
            containerObj["id"] = parts[0];
            containerObj["name"] = parts[1];
            containerObj["image"] = parts[2];
            containerObj["status"] = parts[3];
            containerObj["ports"] = "";
            containerObj["current"] = (parts[1] == containerName);
        }
        
        containerList.append(containerObj);
    }
    
    return containerList;
}