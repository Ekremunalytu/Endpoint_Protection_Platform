#include "../Headers/DockerManager.h"
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QThread>

DockerManager::DockerManager(QObject *parent) : QObject(parent) {
    // Docker process ayarları - SeparateChannels kullanarak hata çıktılarını ayrı tutuyoruz
    dockerProcess.setProcessChannelMode(QProcess::SeparateChannels);
    
    // İlk başta container çalışmadığını işaretle
    containerRunning = false;
    containerName = "";
    imageName = "";
    
    // Hata durumunu sıfırla
    clearError();
}

DockerManager::~DockerManager() {
    try {
        if (isContainerRunning()) {
            stopContainer();
        }
    } catch (const std::exception& e) {
        qDebug() << "Exception in ~DockerManager:" << e.what();
    } catch (...) {
        qDebug() << "Unknown exception in ~DockerManager";
    }
    // QProcess member olduğu için delete işlemi kaldırıldı
}

// Hata işleme metotlarının implementasyonu
DockerError DockerManager::lastError() const {
    return m_lastError;
}

DockerError& DockerManager::lastError() {
    return m_lastError;
}

QString DockerManager::lastErrorMessage() const {
    if (m_lastError.hasError()) {
        if (m_lastError.details.isEmpty()) {
            return m_lastError.message;
        } else {
            return QString("%1: %2").arg(m_lastError.message, m_lastError.details);
        }
    }
    return QString();
}

void DockerManager::clearError() const {
    m_lastError = DockerError();
}

void DockerManager::setError(DockerErrorCode code, const QString& message, const QString& details) const {
    m_lastError = DockerError(code, message, details);
}

void DockerManager::logError(const QString& method, const QString& message, const QString& details) const {
    QString logMessage = QString("DockerManager::%1: %2").arg(method, message);
    if (!details.isEmpty()) {
        logMessage += QString(" - %1").arg(details);
    }
    qDebug() << logMessage;
}

void DockerManager::handleException(const QString& method, const std::exception& e) const {
    QString message = QString("Exception in %1: %2").arg(method, e.what());
    logError(method, message);
    setError(DockerErrorCode::UnknownError, message);
}

void DockerManager::handleUnknownException(const QString& method) const {
    QString message = QString("Unknown exception in %1").arg(method);
    logError(method, message);
    setError(DockerErrorCode::UnknownError, message);
}

bool DockerManager::isDockerAvailable() const {
    // Hata durumunu sıfırla
    clearError();
    
    QProcess process;
    process.start("docker", QStringList() << "ps");
    process.waitForFinished();

    // const metodundan mutable bir üye değişkeni değiştiremeyeceğimiz için burada
    // yerel bir değişken oluşturuyoruz
    QProcess localProcess;
    
    if (process.exitCode() == 0) {
        try {
            localProcess.start("docker", QStringList() << "ps");
            
            // Timeout değerini artırıyoruz - bazı ortamlarda daha uzun sürebilir
            if (!localProcess.waitForFinished(10000)) {  // 10 saniye timeout
                setError(DockerErrorCode::TimeoutError, "Docker command timeout");
                logError("isDockerAvailable", "Docker command timeout");
                return false;
            }
            
            if (localProcess.exitCode() != 0) {
                QString errorDetails = localProcess.readAllStandardError();
                setError(DockerErrorCode::DockerNotAvailable, "Docker daemon is not responsive", errorDetails);
                logError("isDockerAvailable", "Docker daemon is not responsive", errorDetails);
                return false;
            }
            
            QString output = localProcess.readAllStandardOutput().trimmed();
            qDebug() << "Docker daemon is responsive: " << output;
            return true;
        } catch (const std::exception& e) {
            handleException("isDockerAvailable", e);
            return false;
        } catch (...) {
            handleUnknownException("isDockerAvailable");
            return false;
        }
    }
    
    setError(DockerErrorCode::DockerNotAvailable, "Docker is not available");
    logError("isDockerAvailable", "Docker is not available");
    return false;
}

bool DockerManager::startContainer(const QString& config) {
    // Hata durumunu sıfırla
    clearError();
    
    try {
        if (!isDockerAvailable()) {
            setError(DockerErrorCode::DockerNotAvailable, "Docker is not available, cannot start container");
            logError("startContainer", "Docker is not available, cannot start container");
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
            setError(DockerErrorCode::ContainerStartFailed, 
                    "Container name or image not specified in config", config);
            logError("startContainer", "Container name or image not specified in config", config);
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
            
            // Konteyner durdurulduktan sonra kısa bir bekleme ekleyelim
            QThread::msleep(1000);
        }
        
        // Önce imajın mevcut olup olmadığını kontrol edelim
        dockerProcess.start("docker", QStringList() << "image" << "inspect" << imageName);
        if (!dockerProcess.waitForFinished(10000)) {
            setError(DockerErrorCode::TimeoutError, "Docker image inspect command timeout");
            logError("startContainer", "Docker image inspect command timeout");
        }
        
        bool imageExists = (dockerProcess.exitCode() == 0);
        
        // Eğer imaj mevcut değilse, çekmeyi deneyelim
        if (!imageExists) {
            qDebug() << "Image not found locally, pulling image:" << imageName;
            
            // İmaj çekme işlemi uzun sürebilir, timeout değerini artıralım
            dockerProcess.start("docker", QStringList() << "pull" << imageName);
            
            // İmaj çekme için daha uzun timeout (2 dakika)
            if (!dockerProcess.waitForFinished(120000)) {
                QString errorDetails = dockerProcess.readAllStandardError();
                setError(DockerErrorCode::TimeoutError, "Docker pull command timeout", errorDetails);
                logError("startContainer", "Docker pull command timeout", errorDetails);
                
                // İmaj çekemedik, mevcut bir imaj var mı kontrol edelim
                dockerProcess.start("docker", QStringList() << "image" << "inspect" << imageName);
                dockerProcess.waitForFinished(10000);
                
                if (dockerProcess.exitCode() != 0) {
                    // İmaj bulunamadı ve çekilemedi
                    setError(DockerErrorCode::ImageNotFound, 
                             "Failed to pull image and image does not exist locally", imageName);
                    logError("startContainer", 
                             "Failed to pull image and image does not exist locally", imageName);
                    return false;
                } else {
                    // İmaj zaten varmış
                    qDebug() << "Image exists locally, continuing with existing image:" << imageName;
                }
            } else if (dockerProcess.exitCode() != 0) {
                // İmaj çekme başarısız oldu
                QString errorOutput = dockerProcess.readAllStandardError();
                setError(DockerErrorCode::ImagePullFailed, 
                         "Failed to pull image", imageName + ": " + errorOutput);
                logError("startContainer", "Failed to pull image", imageName + ": " + errorOutput);
                
                // Bakın yerel bir imaj var mı
                dockerProcess.start("docker", QStringList() << "image" << "inspect" << imageName);
                dockerProcess.waitForFinished(10000);
                
                if (dockerProcess.exitCode() != 0) {
                    setError(DockerErrorCode::ImageNotFound, 
                             "No local image found either, cannot proceed", imageName);
                    logError("startContainer", "No local image found either, cannot proceed", imageName);
                    return false;
                } else {
                    qDebug() << "Using existing local image:" << imageName;
                }
            } else {
                qDebug() << "Successfully pulled image:" << imageName;
            }
        } else {
            qDebug() << "Image found locally:" << imageName;
        }
        
        // Önce evcut konteyneri kontrol et ve varsa kaldır
        dockerProcess.start("docker", QStringList() << "rm" << "-f" << containerName);
        dockerProcess.waitForFinished(10000);
        
        // Bazı temel dizinleri bağlayalım
        QStringList runArgs;
        runArgs << "run" << "-d" << "--name" << containerName;
        
        // Geçici bir dizin oluştur ve bağla
        QString tempDir = QDir::tempPath() + "/" + containerName;
        QDir().mkpath(tempDir + "/input");
        QDir().mkpath(tempDir + "/output");
        QDir().mkpath(tempDir + "/samples");
        
        runArgs << "-v" << tempDir + "/input:/input";
        runArgs << "-v" << tempDir + "/output:/output";
        runArgs << "-v" << tempDir + "/samples:/samples";
        
        // Containerı detaylı modda başlat ve basit bir komut çalıştır
        runArgs << imageName << "sh" << "-c" << "sleep infinity";
        
        qDebug() << "Running docker container with command:" << runArgs.join(" ");
        
        // Konteyner başlatma
        dockerProcess.start("docker", runArgs);
        
        // Konteyner başlatma için 30 saniye timeout
        if (!dockerProcess.waitForFinished(30000)) {
            QString errorOutput = dockerProcess.readAllStandardError();
            setError(DockerErrorCode::TimeoutError, "Docker run command timeout", errorOutput);
            logError("startContainer", "Docker run command timeout", errorOutput);
            return false;
        }
        
        if (dockerProcess.exitCode() != 0) {
            QString errorOutput = dockerProcess.readAllStandardError();
            setError(DockerErrorCode::ContainerStartFailed, "Failed to start container", errorOutput);
            logError("startContainer", "Failed to start container", errorOutput);
            return false;
        }
        
        // Konteyner çalışıyor mu kontrol et
        if (!isContainerRunning()) {
            setError(DockerErrorCode::ContainerStartFailed, "Container was started but is not running");
            logError("startContainer", "Container was started but is not running");
            return false;
        }
        
        containerRunning = true;
        qDebug() << "Container started successfully:" << containerName;
        return true;
    } catch (const std::exception& e) {
        handleException("startContainer", e);
        return false;
    } catch (...) {
        handleUnknownException("startContainer");
        return false;
    }
}

bool DockerManager::stopContainer(const QString& containerName) {
    // Hata durumunu sıfırla
    clearError();
    
    try {
        if (containerName.isEmpty()) {
            setError(DockerErrorCode::ContainerStopFailed, "No container name specified, cannot stop container");
            logError("stopContainer", "No container name specified, cannot stop container");
            return false;
        }
        
        qDebug() << "Stopping container:" << containerName;
        
        // İlk önce konteyneri durdur
        dockerProcess.start("docker", QStringList() << "stop" << containerName);
        if (!dockerProcess.waitForFinished(20000)) {
            setError(DockerErrorCode::TimeoutError, "Docker stop command timeout, forcing removal");
            logError("stopContainer", "Docker stop command timeout, forcing removal");
        }
        
        // Sonra konteyneri kaldır (zorla kaldır)
        dockerProcess.start("docker", QStringList() << "rm" << "-f" << containerName);
        if (!dockerProcess.waitForFinished(20000)) {
            setError(DockerErrorCode::TimeoutError, "Docker rm command timeout");
            logError("stopContainer", "Docker rm command timeout");
        }
        
        // Eğer durdurulan konteyner mevcut konteyner ise, durumunu güncelle
        if (this->containerName == containerName) {
            containerRunning = false;
        }
        
        qDebug() << "Container stopped and removed:" << containerName;
        return true;
    } catch (const std::exception& e) {
        handleException("stopContainer", e);
        return false;
    } catch (...) {
        handleUnknownException("stopContainer");
        return false;
    }
}

// İç kullanım için overload edilmiş metot
bool DockerManager::stopContainer() {
    if (!containerName.isEmpty()) {
        return stopContainer(containerName);
    }
    setError(DockerErrorCode::ContainerStopFailed, "No container name specified for current instance");
    logError("stopContainer", "No container name specified for current instance");
    return false;
}

bool DockerManager::isContainerRunning(const QString& containerName) {
    // Hata durumunu sıfırla
    clearError();
    
    try {
        if (containerName.isEmpty()) {
            setError(DockerErrorCode::ContainerNotFound, "No container name specified, assuming not running");
            logError("isContainerRunning", "No container name specified, assuming not running");
            return false;
        }
        
        dockerProcess.start("docker", QStringList() << "ps" << "-q" << "-f" << "name=" + containerName);
        
        if (!dockerProcess.waitForFinished(10000)) {
            setError(DockerErrorCode::TimeoutError, "Docker ps command timeout");
            logError("isContainerRunning", "Docker ps command timeout");
            return false;
        }
        
        QString output = dockerProcess.readAllStandardOutput().trimmed();
        bool isRunning = !output.isEmpty();
        
        if (this->containerName == containerName) {
            containerRunning = isRunning;
        }
        
        return isRunning;
    } catch (const std::exception& e) {
        handleException("isContainerRunning", e);
        return false;
    } catch (...) {
        handleUnknownException("isContainerRunning");
        return false;
    }
}

// İç kullanım için overload edilmiş metot - parametresi yok
bool DockerManager::isContainerRunning() {
    if (containerName.isEmpty()) {
        setError(DockerErrorCode::ContainerNotFound, "No container name specified for current instance");
        logError("isContainerRunning", "No container name specified for current instance");
        return false;
    }
    return isContainerRunning(containerName);
}

QString DockerManager::executeCommand(const QString& command) {
    // Hata durumunu sıfırla
    clearError();
    
    try {
        if (!isContainerRunning()) {
            setError(DockerErrorCode::ContainerNotFound, 
                     "Container is not running, cannot execute command", command);
            logError("executeCommand", "Container is not running, cannot execute command", command);
            return QString();
        }
        
        qDebug() << "Executing command in container:" << command;
        
        dockerProcess.start("docker", QStringList() << "exec" << containerName << "sh" << "-c" << command);
        
        // Komut yürütmesi için daha uzun bir timeout (60 saniye)
        if (!dockerProcess.waitForFinished(60000)) {
            setError(DockerErrorCode::TimeoutError, "Docker exec command timeout", command);
            logError("executeCommand", "Docker exec command timeout", command);
            return QString();
        }
        
        if (dockerProcess.exitCode() != 0) {
            QString errorOutput = dockerProcess.readAllStandardError();
            setError(DockerErrorCode::CommandExecutionFailed, 
                     "Failed to execute command in container", 
                     command + ": " + errorOutput);
            logError("executeCommand", 
                     "Failed to execute command in container", 
                     command + ": " + errorOutput);
            return QString();
        }
        
        QString output = dockerProcess.readAllStandardOutput().trimmed();
        return output;
    } catch (const std::exception& e) {
        handleException("executeCommand", e);
        return QString();
    } catch (...) {
        handleUnknownException("executeCommand");
        return QString();
    }
}

bool DockerManager::copyFileToContainer(const QString& localPath, const QString& containerPath) {
    // Hata durumunu sıfırla
    clearError();
    
    try {
        if (!isContainerRunning()) {
            setError(DockerErrorCode::ContainerNotFound, 
                     "Container is not running, cannot copy file", 
                     containerName + " -> " + containerPath);
            logError("copyFileToContainer", "Container is not running, cannot copy file");
            return false;
        }
        
        QFileInfo fileInfo(localPath);
        if (!fileInfo.exists() || !fileInfo.isFile()) {
            setError(DockerErrorCode::CopyToContainerFailed, 
                     "Local file does not exist", localPath);
            logError("copyFileToContainer", "Local file does not exist", localPath);
            return false;
        }
        
        dockerProcess.start("docker", QStringList() << "cp" << localPath << containerName + ":" + containerPath);
        
        if (!dockerProcess.waitForFinished(30000)) {
            setError(DockerErrorCode::TimeoutError, "Docker cp command timeout");
            logError("copyFileToContainer", "Docker cp command timeout");
            return false;
        }
        
        if (dockerProcess.exitCode() != 0) {
            QString errorOutput = dockerProcess.readAllStandardError();
            setError(DockerErrorCode::CopyToContainerFailed, 
                     "Failed to copy file to container", errorOutput);
            logError("copyFileToContainer", "Failed to copy file to container", errorOutput);
            return false;
        }
        
        qDebug() << "File copied to container successfully: " << localPath << " -> " << containerPath;
        return true;
    } catch (const std::exception& e) {
        handleException("copyFileToContainer", e);
        return false;
    } catch (...) {
        handleUnknownException("copyFileToContainer");
        return false;
    }
}

bool DockerManager::copyFileFromContainer(const QString& containerPath, const QString& localPath) {
    // Hata durumunu sıfırla
    clearError();
    
    try {
        if (!isContainerRunning()) {
            setError(DockerErrorCode::ContainerNotFound, 
                     "Container is not running, cannot copy file", 
                     containerPath + " -> " + localPath);
            logError("copyFileFromContainer", "Container is not running, cannot copy file");
            return false;
        }
        
        // Yerel dizinin var olduğundan emin olalım
        QFileInfo dirInfo(QFileInfo(localPath).absolutePath());
        if (!dirInfo.exists() || !dirInfo.isDir()) {
            QDir().mkpath(dirInfo.absolutePath());
            if (!QDir().exists(dirInfo.absolutePath())) {
                setError(DockerErrorCode::CopyFromContainerFailed, 
                         "Failed to create local directory", dirInfo.absolutePath());
                logError("copyFileFromContainer", "Failed to create local directory", dirInfo.absolutePath());
                return false;
            }
        }
        
        dockerProcess.start("docker", QStringList() << "cp" << containerName + ":" + containerPath << localPath);
        
        if (!dockerProcess.waitForFinished(30000)) {
            setError(DockerErrorCode::TimeoutError, "Docker cp command timeout");
            logError("copyFileFromContainer", "Docker cp command timeout");
            return false;
        }
        
        if (dockerProcess.exitCode() != 0) {
            QString errorOutput = dockerProcess.readAllStandardError();
            setError(DockerErrorCode::CopyFromContainerFailed, 
                     "Failed to copy file from container", 
                     containerPath + " -> " + localPath + ": " + errorOutput);
            logError("copyFileFromContainer", "Failed to copy file from container", errorOutput);
            return false;
        }
        
        // Check if the file exists
        QFileInfo fileInfo(localPath);
        if (!fileInfo.exists()) {
            setError(DockerErrorCode::CopyFromContainerFailed, 
                     "File was not copied successfully to local path", localPath);
            logError("copyFileFromContainer", "File was not copied successfully to local path", localPath);
            return false;
        }
        
        qDebug() << "File copied from container successfully: " << containerPath << " -> " << localPath;
        return true;
    } catch (const std::exception& e) {
        handleException("copyFileFromContainer", e);
        return false;
    } catch (...) {
        handleUnknownException("copyFileFromContainer");
        return false;
    }
}

QJsonArray DockerManager::listContainers(bool showAll) {
    // Hata durumunu sıfırla
    clearError();
    
    QJsonArray containerList;
    
    try {
        if (!isDockerAvailable()) {
            setError(DockerErrorCode::DockerNotAvailable, 
                     "Docker is not available, cannot list containers");
            logError("listContainers", "Docker is not available, cannot list containers");
            return containerList;
        }
        
        // Docker komutunu oluştur
        QStringList args;
        args << "ps";
        if (showAll) {
            args << "-a";  // Tüm konteynerleri göster (durmuş olanlar dahil)
        }
        args << "--format" << "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}";
        
        // Komutu çalıştır
        dockerProcess.start("docker", args);
        
        if (!dockerProcess.waitForFinished(15000)) {
            setError(DockerErrorCode::TimeoutError, "Docker ps command timeout");
            logError("listContainers", "Docker ps command timeout");
            return containerList;
        }
        
        // Sonucu analiz et
        if (dockerProcess.exitCode() != 0) {
            QString errorOutput = dockerProcess.readAllStandardError();
            setError(DockerErrorCode::CommandExecutionFailed, 
                    "Failed to get Docker container list", errorOutput);
            logError("listContainers", "Failed to get Docker container list", errorOutput);
            return containerList;
        }
        
        QString output = dockerProcess.readAllStandardOutput().trimmed();
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
    } catch (const std::exception& e) {
        handleException("listContainers", e);
        return containerList;
    } catch (...) {
        handleUnknownException("listContainers");
        return containerList;
    }
}

// Interface metotlarını implement et
QJsonArray DockerManager::getDockerContainers() {
    // Hata durumunu sıfırla
    clearError();
    
    try {
        if (!isDockerAvailable()) {
            setError(DockerErrorCode::DockerNotAvailable, 
                     "Docker is not available, cannot list containers");
            logError("getDockerContainers", "Docker is not available, cannot list containers");
            return QJsonArray();
        }
    
        return listContainers(true); // Tüm konteynerleri göster
    } catch (const std::exception& e) {
        handleException("getDockerContainers", e);
        return QJsonArray();
    } catch (...) {
        handleUnknownException("getDockerContainers");
        return QJsonArray();
    }
}

QJsonArray DockerManager::getDockerImages() {
    // Hata durumunu sıfırla
    clearError();

    QJsonArray imageList;
    
    try {
        if (!isDockerAvailable()) {
            setError(DockerErrorCode::DockerNotAvailable, 
                     "Docker is not available, cannot list images");
            logError("getDockerImages", "Docker is not available, cannot list images");
            return imageList;
        }
        
        // Docker komutunu oluştur
        QStringList args;
        args << "images" << "--format" << "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}";
        
        // Komutu çalıştır
        dockerProcess.start("docker", args);
        
        if (!dockerProcess.waitForFinished(10000)) {
            setError(DockerErrorCode::TimeoutError, "Docker images command timeout");
            logError("getDockerImages", "Docker images command timeout");
            return imageList;
        }
        
        // Sonucu analiz et
        if (dockerProcess.exitCode() != 0) {
            QString errorOutput = dockerProcess.readAllStandardError();
            setError(DockerErrorCode::CommandExecutionFailed, 
                    "Failed to get Docker image list", errorOutput);
            logError("getDockerImages", "Failed to get Docker image list", errorOutput);
            return imageList;
        }
        
        QString output = dockerProcess.readAllStandardOutput().trimmed();
        QStringList images = output.split("\n");
        
        // Her imajı JSON objesine dönüştür
        for (const QString& image : images) {
            if (image.trimmed().isEmpty()) continue;
            
            QStringList parts = image.split("\t");
            QJsonObject imageObj;
            
            if (parts.size() >= 4) {
                imageObj["id"] = parts[0];
                imageObj["name"] = parts[1];
                imageObj["tag"] = parts[2];
                imageObj["size"] = parts[3];
                imageObj["current"] = (parts[1] + ":" + parts[2] == imageName); // Mevcut imaj mı?
            }
            
            imageList.append(imageObj);
        }
        
        return imageList;
    } catch (const std::exception& e) {
        handleException("getDockerImages", e);
        return imageList;
    } catch (...) {
        handleUnknownException("getDockerImages");
        return imageList;
    }
}

bool DockerManager::runContainer(const QString& imageName, const QString& containerName, const QStringList& params) {
    // Hata durumunu sıfırla
    clearError();
    
    try {
        if (imageName.isEmpty()) {
            setError(DockerErrorCode::ImageNotFound, "Image name is empty");
            logError("runContainer", "Image name is empty");
            return false;
        }
        
        if (containerName.isEmpty()) {
            setError(DockerErrorCode::ContainerStartFailed, "Container name is empty");
            logError("runContainer", "Container name is empty");
            return false;
        }
        
        QString config = "name=" + containerName + ",image=" + imageName;
        return startContainer(config);
    } catch (const std::exception& e) {
        handleException("runContainer", e);
        return false;
    } catch (...) {
        handleUnknownException("runContainer");
        return false;
    }
}

QString DockerManager::getContainerLogs(const QString& containerName) {
    // Hata durumunu sıfırla
    clearError();
    
    try {
        if (!isDockerAvailable()) {
            setError(DockerErrorCode::DockerNotAvailable, 
                     "Docker is not available, cannot get container logs");
            logError("getContainerLogs", "Docker is not available, cannot get container logs");
            return QString();
        }
        
        if (containerName.isEmpty()) {
            setError(DockerErrorCode::ContainerNotFound, "Container name is empty");
            logError("getContainerLogs", "Container name is empty");
            return QString();
        }
        
        dockerProcess.start("docker", QStringList() << "logs" << containerName);
        
        if (!dockerProcess.waitForFinished(20000)) {
            setError(DockerErrorCode::TimeoutError, "Docker logs command timeout");
            logError("getContainerLogs", "Docker logs command timeout");
            return QString();
        }
        
        if (dockerProcess.exitCode() != 0) {
            QString errorOutput = dockerProcess.readAllStandardError();
            setError(DockerErrorCode::CommandExecutionFailed, 
                    "Failed to get container logs", errorOutput);
            logError("getContainerLogs", "Failed to get container logs", errorOutput);
            return QString("Failed to get logs: ") + errorOutput;
        }
        
        return dockerProcess.readAllStandardOutput();
    } catch (const std::exception& e) {
        handleException("getContainerLogs", e);
        return QString("Exception occurred: ") + e.what();
    } catch (...) {
        handleUnknownException("getContainerLogs");
        return QString("Unknown exception occurred");
    }
}