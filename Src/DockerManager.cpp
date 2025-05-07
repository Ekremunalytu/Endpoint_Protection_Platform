#include "../Headers/DockerManager.h"
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QJsonArray>
#include <QJsonObject>
#include <QThread>

DockerManager::DockerManager(QObject *parent) : QObject(parent), dockerProcess(new QProcess(this)), containerRunning(false) {
    // Docker process ayarları - SeparateChannels kullanarak hata çıktılarını ayrı tutuyoruz
    dockerProcess->setProcessChannelMode(QProcess::SeparateChannels);
    
    // İlk başta container çalışmadığını işaretle
    containerRunning = false;
    containerName = "";
    imageName = "";
}

DockerManager::~DockerManager() {
    if (isContainerRunning()) {
        stopContainer();
    }
    delete dockerProcess;
}

bool DockerManager::isDockerAvailable() {
    QProcess process;
    process.start("docker", QStringList() << "ps"); // Changed from docker --version to docker ps
    process.waitForFinished();

    if (process.exitCode() == 0) {
        try {
            dockerProcess->start("docker", QStringList() << "ps");
            
            // Timeout değerini artırıyoruz - bazı ortamlarda daha uzun sürebilir
            if (!dockerProcess->waitForFinished(10000)) {  // 10 saniye timeout
                qDebug() << "Docker command timeout";
                return false;
            }
            
            if (dockerProcess->exitCode() != 0) {
                qDebug() << "Docker daemon is not responsive: " << dockerProcess->readAllStandardError();
                return false;
            }
            
            QString output = dockerProcess->readAllStandardOutput().trimmed();
            qDebug() << "Docker daemon is responsive: " << output;
            return true;
        } catch (const std::exception& e) {
            qDebug() << "Exception in isDockerAvailable:" << e.what();
            return false;
        } catch (...) {
            qDebug() << "Unknown exception in isDockerAvailable";
            return false;
        }
    }
    return false; // Added to ensure a value is always returned
}

bool DockerManager::startContainer(const QString& config) {
    try {
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
            
            // Konteyner durdurulduktan sonra kısa bir bekleme ekleyelim
            QThread::msleep(1000);
        }
        
        // Önce imajın mevcut olup olmadığını kontrol edelim
        dockerProcess->start("docker", QStringList() << "image" << "inspect" << imageName);
        if (!dockerProcess->waitForFinished(10000)) {
            qDebug() << "Docker image inspect command timeout";
        }
        
        bool imageExists = (dockerProcess->exitCode() == 0);
        
        // Eğer imaj mevcut değilse, çekmeyi deneyelim
        if (!imageExists) {
            qDebug() << "Image not found locally, pulling image:" << imageName;
            
            // İmaj çekme işlemi uzun sürebilir, timeout değerini artıralım
            dockerProcess->start("docker", QStringList() << "pull" << imageName);
            
            // İmaj çekme için daha uzun timeout (2 dakika)
            if (!dockerProcess->waitForFinished(120000)) {
                qDebug() << "Docker pull command timeout";
                qDebug() << "Error pulling image:" << dockerProcess->readAllStandardError();
                
                // İmaj çekemedik, mevcut bir imaj var mı kontrol edelim
                dockerProcess->start("docker", QStringList() << "image" << "inspect" << imageName);
                dockerProcess->waitForFinished(10000);
                
                if (dockerProcess->exitCode() != 0) {
                    // İmaj bulunamadı ve çekilemedi
                    qDebug() << "Failed to pull image and image does not exist locally:" << imageName;
                    return false;
                } else {
                    // İmaj zaten varmış
                    qDebug() << "Image exists locally, continuing with existing image:" << imageName;
                }
            } else if (dockerProcess->exitCode() != 0) {
                // İmaj çekme başarısız oldu
                QString errorOutput = dockerProcess->readAllStandardError();
                qDebug() << "Failed to pull image:" << imageName;
                qDebug() << "Error:" << errorOutput;
                
                // Bakın yerel bir imaj var mı
                dockerProcess->start("docker", QStringList() << "image" << "inspect" << imageName);
                dockerProcess->waitForFinished(10000);
                
                if (dockerProcess->exitCode() != 0) {
                    qDebug() << "No local image found either, cannot proceed";
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
        dockerProcess->start("docker", QStringList() << "rm" << "-f" << containerName);
        dockerProcess->waitForFinished(10000);
        
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
        dockerProcess->start("docker", runArgs);
        
        // Konteyner başlatma için 30 saniye timeout
        if (!dockerProcess->waitForFinished(30000)) {
            qDebug() << "Docker run command timeout";
            QString errorOutput = dockerProcess->readAllStandardError();
            qDebug() << "Error starting container:" << errorOutput;
            return false;
        }
        
        if (dockerProcess->exitCode() != 0) {
            QString errorOutput = dockerProcess->readAllStandardError();
            qDebug() << "Failed to start container:" << errorOutput;
            return false;
        }
        
        // Konteyner çalışıyor mu kontrol et
        if (!isContainerRunning()) {
            qDebug() << "Container was started but is not running";
            return false;
        }
        
        containerRunning = true;
        qDebug() << "Container started successfully:" << containerName;
        return true;
    } catch (const std::exception& e) {
        qDebug() << "Exception in startContainer:" << e.what();
        return false;
    } catch (...) {
        qDebug() << "Unknown exception in startContainer";
        return false;
    }
}

void DockerManager::stopContainer() {
    try {
        if (containerName.isEmpty()) {
            qDebug() << "No container name specified, cannot stop container";
            containerRunning = false;
            return;
        }
        
        qDebug() << "Stopping container:" << containerName;
        
        // İlk önce konteyneri durdur
        dockerProcess->start("docker", QStringList() << "stop" << containerName);
        if (!dockerProcess->waitForFinished(20000)) {
            qDebug() << "Docker stop command timeout, forcing removal";
        }
        
        // Sonra konteyneri kaldır (zorla kaldır)
        dockerProcess->start("docker", QStringList() << "rm" << "-f" << containerName);
        if (!dockerProcess->waitForFinished(20000)) {
            qDebug() << "Docker rm command timeout";
        }
        
        containerRunning = false;
        qDebug() << "Container stopped and removed:" << containerName;
    } catch (const std::exception& e) {
        qDebug() << "Exception in stopContainer:" << e.what();
        containerRunning = false;
    } catch (...) {
        qDebug() << "Unknown exception in stopContainer";
        containerRunning = false;
    }
}

bool DockerManager::isContainerRunning() {
    try {
        if (containerName.isEmpty()) {
            qDebug() << "No container name specified, assuming not running";
            containerRunning = false;
            return false;
        }
        
        dockerProcess->start("docker", QStringList() << "ps" << "-q" << "-f" << "name=" + containerName);
        
        if (!dockerProcess->waitForFinished(10000)) {
            qDebug() << "Docker ps command timeout";
            return containerRunning;  // Son bilinen durumu döndür
        }
        
        QString output = dockerProcess->readAllStandardOutput().trimmed();
        containerRunning = !output.isEmpty();
        return containerRunning;
    } catch (const std::exception& e) {
        qDebug() << "Exception in isContainerRunning:" << e.what();
        return false;
    } catch (...) {
        qDebug() << "Unknown exception in isContainerRunning";
        return false;
    }
}

QString DockerManager::executeCommand(const QString& command) {
    try {
        if (!isContainerRunning()) {
            qDebug() << "Container is not running, cannot execute command:" << command;
            return QString();
        }
        
        qDebug() << "Executing command in container:" << command;
        
        dockerProcess->start("docker", QStringList() << "exec" << containerName << "sh" << "-c" << command);
        
        // Komut yürütmesi için daha uzun bir timeout (60 saniye)
        if (!dockerProcess->waitForFinished(60000)) {
            qDebug() << "Docker exec command timeout";
            return QString();
        }
        
        if (dockerProcess->exitCode() != 0) {
            QString errorOutput = dockerProcess->readAllStandardError();
            qDebug() << "Failed to execute command in container:" << errorOutput;
            return QString();
        }
        
        QString output = dockerProcess->readAllStandardOutput().trimmed();
        return output;
    } catch (const std::exception& e) {
        qDebug() << "Exception in executeCommand:" << e.what();
        return QString();
    } catch (...) {
        qDebug() << "Unknown exception in executeCommand";
        return QString();
    }
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