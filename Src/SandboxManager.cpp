#include "../Headers/SandboxManager.h"
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QDateTime>

SandboxManager::SandboxManager(QObject *parent) : QObject(parent) {
    dockerManager = new DockerManager(this);
    sandboxImageName = "cuckoo/cuckoo:latest"; // Örnek bir sandbox Docker imajı
    analysisTimeout = 120; // Saniye cinsinden varsayılan analiz süresi
    
    // İzlenecek davranışlar
    monitoredBehaviors << "filesystem" << "network" << "process" << "registry";
}

SandboxManager::~SandboxManager() {
    delete dockerManager;
}

bool SandboxManager::initialize() {
    if (!dockerManager->isDockerAvailable()) {
        qDebug() << "Docker is not available, cannot initialize sandbox";
        return false;
    }
    
    qDebug() << "Initializing Sandbox manager";
    
    // Sandbox için daha uygun bir Docker imajı kullanalım
    // core-sandbox veya similar-sandbox gibi daha hafif bir sandbox imajı kullanabiliriz
    sandboxImageName = "seccomp/faasm-sandbox:latest";
    
    qDebug() << "Sandbox initialized with image: " << sandboxImageName;
    return true;
}

bool SandboxManager::analyzeFile(const QString& filePath) {
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        qDebug() << "File does not exist: " << filePath;
        return false;
    }
    
    // Container konfigürasyonu
    QString containerConfig = "name=sandbox_container,image=" + sandboxImageName;
    
    // Container'ı başlatalım
    if (!dockerManager->startContainer(containerConfig)) {
        qDebug() << "Failed to start sandbox container";
        return false;
    }
    
    // Dosyayı container'a kopyalayalım
    QString containerPath = "/samples/" + fileInfo.fileName();
    if (!dockerManager->copyFileToContainer(filePath, containerPath)) {
        qDebug() << "Failed to copy file to sandbox container";
        dockerManager->stopContainer();
        return false;
    }
    
    // Analiz işlemini başlatalım
    QString command = "python /cuckoo/cuckoo.py submit " + containerPath + 
                     " --timeout=" + QString::number(analysisTimeout);
    QString result = dockerManager->executeCommand(command);
    
    if (result.isEmpty() || result.contains("error", Qt::CaseInsensitive)) {
        qDebug() << "Sandbox analysis failed: " << result;
        dockerManager->stopContainer();
        return false;
    }
    
    qDebug() << "Sandbox analysis started successfully";
    qDebug() << "Analysis result: " << result;
    
    // Container'ı henüz durdurmuyoruz, çünkü analiz sonuçlarını almamız gerekebilir
    return true;
}

QJsonObject SandboxManager::getAnalysisResults() {
    QJsonObject results;
    
    // Birleştirilmiş sonuçları oluştur
    results["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    results["timeout"] = analysisTimeout;
    
    // Farklı aktivite türlerine göre sonuçları ekleyelim
    results["filesystem"] = parseFileSystemActivity();
    results["network"] = parseNetworkActivity();
    results["process"] = parseProcessActivity();
    results["registry"] = parseRegistryActivity();
    
    // Tamamlandığında container'ı durdur
    dockerManager->stopContainer();
    
    return results;
}

QJsonObject SandboxManager::parseFileSystemActivity() {
    QJsonObject fileSystemActivity;
    
    // Dosya sistemi aktivitelerini getir
    QString command = "cat /cuckoo/storage/analyses/latest/reports/report.json | jq .behavior.summary.files";
    QString result = dockerManager->executeCommand(command);
    
    QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8());
    if (!doc.isNull() && doc.isArray()) {
        fileSystemActivity["accessed_files"] = doc.array();
    } else {
        fileSystemActivity["accessed_files"] = QJsonArray();
    }
    
    // Tehlikeli dosya işlemleri
    fileSystemActivity["suspicious_writes"] = QJsonArray();
    fileSystemActivity["deleted_files"] = QJsonArray();
    
    return fileSystemActivity;
}

QJsonObject SandboxManager::parseNetworkActivity() {
    QJsonObject networkActivity;
    
    // Ağ aktivitelerini getir
    QString command = "cat /cuckoo/storage/analyses/latest/reports/report.json | jq .network";
    QString result = dockerManager->executeCommand(command);
    
    QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8());
    if (!doc.isNull() && doc.isObject()) {
        networkActivity = doc.object();
    } else {
        // Varsayılan boş yapılar
        networkActivity["dns_requests"] = QJsonArray();
        networkActivity["http_requests"] = QJsonArray();
        networkActivity["tcp_connections"] = QJsonArray();
        networkActivity["udp_connections"] = QJsonArray();
    }
    
    return networkActivity;
}

QJsonObject SandboxManager::parseProcessActivity() {
    QJsonObject processActivity;
    
    // İşlem aktivitelerini getir
    QString command = "cat /cuckoo/storage/analyses/latest/reports/report.json | jq .behavior.processes";
    QString result = dockerManager->executeCommand(command);
    
    QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8());
    if (!doc.isNull() && doc.isArray()) {
        processActivity["processes"] = doc.array();
    } else {
        processActivity["processes"] = QJsonArray();
    }
    
    return processActivity;
}

QJsonObject SandboxManager::parseRegistryActivity() {
    QJsonObject registryActivity;
    
    // Kayıt defteri aktivitelerini getir
    QString command = "cat /cuckoo/storage/analyses/latest/reports/report.json | jq .behavior.summary.keys";
    QString result = dockerManager->executeCommand(command);
    
    QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8());
    if (!doc.isNull() && doc.isArray()) {
        registryActivity["registry_keys"] = doc.array();
    } else {
        registryActivity["registry_keys"] = QJsonArray();
    }
    
    // Tehlikeli kayıt defteri işlemleri
    registryActivity["suspicious_registry_operations"] = QJsonArray();
    
    return registryActivity;
}