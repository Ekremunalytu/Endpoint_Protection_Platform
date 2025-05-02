#include "../Headers/CdrManager.h"
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QCryptographicHash>

CdrManager::CdrManager(QObject *parent) : QObject(parent) {
    dockerManager = new DockerManager(this);
    cdrImageName = "opendxl/opendxl-file-transfer-service:latest"; // Örnek bir CDR Docker imajı
    outputDir = QDir::tempPath() + "/cdr_output";
    
    // Çıktı dizininin var olduğundan emin olalım
    QDir().mkpath(outputDir);
}

CdrManager::~CdrManager() {
    delete dockerManager;
}

bool CdrManager::initialize() {
    if (!dockerManager->isDockerAvailable()) {
        qDebug() << "Docker is not available, cannot initialize CDR";
        return false;
    }
    
    qDebug() << "Initializing CDR manager with image:" << cdrImageName;
    
    // CDR için uygun bir Docker imajı kullanın
    // Örnek imaj: dannybeckett/disarm - Bu bir açık kaynaklı CDR uygulamasıdır
    // Gerçek uygulamada, kendi CDR imajınızı veya güvenilir bir imaj kullanabilirsiniz
    cdrImageName = "dannybeckett/disarm:latest";
    
    // Geçici dizini oluştur
    outputDir = QDir::tempPath() + "/cdr_output";
    QDir().mkpath(outputDir);
    
    qDebug() << "CDR initialized successfully with image:" << cdrImageName;
    qDebug() << "Output directory:" << outputDir;
    
    return true;
}

bool CdrManager::processFile(const QString& filePath) {
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        qDebug() << "File does not exist: " << filePath;
        return false;
    }
    
    // Container adını ve özellikleri yapılandıralım
    QString containerConfig = "name=cdr_container,image=" + cdrImageName;
    
    // Container'ı başlatalım
    if (!dockerManager->startContainer(containerConfig)) {
        qDebug() << "Failed to start CDR container";
        return false;
    }
    
    // Dosyayı container'a kopyalayalım
    QString containerPath = "/input/" + fileInfo.fileName();
    if (!dockerManager->copyFileToContainer(filePath, containerPath)) {
        qDebug() << "Failed to copy file to container";
        dockerManager->stopContainer();
        return false;
    }
    
    // CDR işlemini çalıştıralım - disarm imajı için uygun komut
    QString command = "disarm sanitize " + containerPath + " --output /output/";
    QString result = dockerManager->executeCommand(command);
    
    qDebug() << "CDR process result: " << result;
    
    // İşlenen dosyanın adını oluştur
    QString outputFileName = generateOutputFilename(filePath);
    
    // İşlenen dosyayı container'dan kopyalayalım
    // disarm genellikle dosyayı container içinde /output/ dizinine kaydeder
    QString containerOutputPath = "/output/" + fileInfo.fileName() + "_sanitized";
    QString localOutputPath = outputDir + "/" + outputFileName;
    
    if (!dockerManager->copyFileFromContainer(containerOutputPath, localOutputPath)) {
        qDebug() << "Failed to copy processed file from container, trying alternative path";
        
        // Alternatif bir dosya yolu deneyelim
        containerOutputPath = "/output/" + fileInfo.fileName();
        
        if (!dockerManager->copyFileFromContainer(containerOutputPath, localOutputPath)) {
            qDebug() << "Failed to copy processed file from container";
            dockerManager->stopContainer();
            return false;
        }
    }
    
    // Container'ı durdur
    dockerManager->stopContainer();
    
    qDebug() << "File processed successfully: " << localOutputPath;
    return true;
}

QString CdrManager::getCleanedFilePath(const QString& originalFilePath) {
    QFileInfo fileInfo(originalFilePath);
    return outputDir + "/" + generateOutputFilename(originalFilePath);
}

QString CdrManager::generateOutputFilename(const QString& inputFilePath) {
    QFileInfo fileInfo(inputFilePath);
    QString baseName = fileInfo.baseName();
    QString suffix = fileInfo.suffix();
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
    
    // Temiz dosya adını oluşturalım
    return baseName + "_cleaned_" + timestamp + "." + suffix;
}

QJsonObject CdrManager::parseResults(const QString& resultData) {
    QJsonObject result;
    QJsonDocument doc = QJsonDocument::fromJson(resultData.toUtf8());
    
    if (doc.isNull() || !doc.isObject()) {
        qDebug() << "Invalid JSON result data";
        result["status"] = "error";
        result["message"] = "Invalid result data format";
        return result;
    }
    
    return doc.object();
}