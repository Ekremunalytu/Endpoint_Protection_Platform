#include "../Headers/SandboxManager.h"
#include <QFileInfo>
#include <QDir>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>
#include <QThread>

SandboxManager::SandboxManager(QObject *parent) : QObject(parent) {
    dockerManager = new DockerManager(this);
    sandboxImageName = ""; // Boş başlatılıyor, kullanıcı seçecek
    resultsDir = QDir::tempPath() + "/sandbox_results";
    analysisTimeout = 300; // 5 dakikalık varsayılan timeout değeri
    
    // Sonuçlar dizininin var olduğundan emin olalım
    QDir().mkpath(resultsDir);
}

SandboxManager::~SandboxManager() {
    // Düzgün temizlik
    try {
        if (dockerManager) {
            if (dockerManager->isContainerRunning()) {
                dockerManager->stopContainer();
            }
            delete dockerManager;
            dockerManager = nullptr;
        }
    } catch (...) {
        qDebug() << "Exception while cleaning up in SandboxManager destructor";
    }
}

bool SandboxManager::initialize() {
    try {
        if (!dockerManager || !dockerManager->isDockerAvailable()) {
            qDebug() << "Docker is not available, cannot initialize Sandbox";
            return false;
        }
        
        // İmaj seçilmemişse sandbox başlatılamaz
        if (sandboxImageName.isEmpty()) {
            qDebug() << "Sandbox image not selected, please choose an image first";
            return false;
        }
        
        qDebug() << "Initializing Sandbox manager with image:" << sandboxImageName;
        
        // Sonuçlar dizinini oluştur
        QDir().mkpath(resultsDir);
        
        qDebug() << "Sandbox initialized successfully with image:" << sandboxImageName;
        qDebug() << "Results directory:" << resultsDir;
        
        return true;
    } catch (const std::exception& e) {
        qDebug() << "Exception in initialize:" << e.what();
        return false;
    } catch (...) {
        qDebug() << "Unknown exception in initialize";
        return false;
    }
}

void SandboxManager::setSandboxImageName(const QString& imageName) {
    if (imageName.isEmpty()) {
        qDebug() << "Empty image name provided, cannot set";
        return;
    }
    
    sandboxImageName = imageName;
    qDebug() << "Sandbox image set to:" << sandboxImageName;
}

QString SandboxManager::getCurrentImageName() const {
    return sandboxImageName;
}

QStringList SandboxManager::getAvailableSandboxImages() const {
    // Önerilen sandbox imajları listesi - Daha basit bir alternatif eklendi
    QStringList images;
    images << "alpine:latest"                        // Basit test için Alpine Linux
          << "seccomp/faasm-sandbox:latest"          // FAASM Sandbox
          << "remnux/thug:latest"                    // Thug (malware analysis)
          << "cuckoo/cuckoo:latest"                  // Cuckoo Sandbox
          << "vipermonkey/vipermonkey:latest"        // ViperMonkey (VBA macro analysis)
          << "remnux/jsunpack-n:latest"              // JSUnpack (JavaScript unpacker)
          << "custom/sandbox:latest";                // Örnek özel imaj
    
    return images;
}

QJsonObject SandboxManager::analyzeFile(const QString& filePath) {
    QJsonObject result;
    
    try {
        // İmaj seçilmemişse analiz yapılamaz
        if (sandboxImageName.isEmpty()) {
            qDebug() << "Sandbox image not selected, please choose an image first";
            result["success"] = false;
            result["message"] = "No sandbox image selected";
            return result;
        }
        
        QFileInfo fileInfo(filePath);
        if (!fileInfo.exists() || !fileInfo.isFile()) {
            qDebug() << "File does not exist: " << filePath;
            result["success"] = false;
            result["message"] = "File not found";
            return result;
        }
        
        // Container adını ve imajını yapılandıralım
        QString containerConfig = "name=sandbox_container,image=" + sandboxImageName;
        
        // Önceki konteyner çalışıyorsa durdur
        if (dockerManager->isContainerRunning()) {
            qDebug() << "Stopping previous container before starting a new one";
            dockerManager->stopContainer();
            QThread::msleep(1000); // Biraz bekleyerek Docker'ın temizlenmesine izin ver
        }
        
        // Container'ı başlatalım
        qDebug() << "Starting sandbox container with config: " << containerConfig;
        if (!dockerManager->startContainer(containerConfig)) {
            qDebug() << "Failed to start sandbox container with image: " << sandboxImageName;
            result["success"] = false;
            result["message"] = "Failed to start sandbox container";
            return result;
        }
        
        // Dosyayı container'a kopyalayalım
        QString containerPath = "/samples/" + fileInfo.fileName();
        qDebug() << "Copying file to container: " << filePath << " -> " << containerPath;
        if (!dockerManager->copyFileToContainer(filePath, containerPath)) {
            qDebug() << "Failed to copy file to sandbox container";
            dockerManager->stopContainer();
            result["success"] = false;
            result["message"] = "Failed to copy file to sandbox container";
            return result;
        }
        
        // Konteyner tipine göre farklı analiz komutları kullanalım
        QString command;
        if (sandboxImageName.contains("cuckoo")) {
            command = "ls -la /cuckoo || echo \"Cuckoo directory not found\"";
            QString checkResult = dockerManager->executeCommand(command);
            qDebug() << "Checking for Cuckoo directory: " << checkResult;
            
            // Cuckoo varsa Cuckoo komutunu, aksi halde basit bir analiz komutu 
            if (checkResult.contains("cuckoo") && !checkResult.contains("not found")) {
                command = "python /cuckoo/cuckoo.py submit " + containerPath + 
                         " --timeout=" + QString::number(analysisTimeout);
            } else {
                command = "file " + containerPath + " && sha256sum " + containerPath;
            }
        } else if (sandboxImageName.contains("thug")) {
            command = "thug " + containerPath + " || file " + containerPath;
        } else if (sandboxImageName.contains("vipermonkey")) {
            command = "vmonkey " + containerPath + " || file " + containerPath;
        } else if (sandboxImageName.contains("jsunpack")) {
            command = "jsunpack-n " + containerPath + " || file " + containerPath;
        } else {
            // Varsayılan basit analiz
            command = "file " + containerPath + " && sha256sum " + containerPath;
        }
        
        qDebug() << "Executing analysis command: " << command;
        QString analysisResult = dockerManager->executeCommand(command);
        
        qDebug() << "Raw analysis output: " << analysisResult;
        
        if (analysisResult.isEmpty()) {
            qDebug() << "Sandbox analysis returned empty result, using alternative analysis";
            // Basit bir analiz komutu dene
            command = "file " + containerPath + " && sha256sum " + containerPath;
            analysisResult = dockerManager->executeCommand(command);
            
            if (analysisResult.isEmpty()) {
                qDebug() << "Alternative analysis failed too";
                dockerManager->stopContainer();
                result["success"] = false;
                result["message"] = "Sandbox analysis failed - no output";
                return result;
            }
        }
        
        if (analysisResult.contains("error", Qt::CaseInsensitive) && 
            analysisResult.contains("permission denied", Qt::CaseInsensitive)) {
            qDebug() << "Permission error in analysis, retrying with chmod";
            
            // Dosya izinlerini düzelt ve tekrar dene
            command = "chmod +x " + containerPath + " && " + command;
            analysisResult = dockerManager->executeCommand(command);
            
            if (analysisResult.isEmpty() || 
                (analysisResult.contains("error", Qt::CaseInsensitive) && 
                 analysisResult.contains("permission denied", Qt::CaseInsensitive))) {
                qDebug() << "Sandbox analysis failed even after permissions fix: " << analysisResult;
                dockerManager->stopContainer();
                result["success"] = false;
                result["message"] = "Sandbox analysis failed - permission error";
                return result;
            }
        }
        
        qDebug() << "Sandbox analysis completed with output: " << analysisResult;
        
        result["success"] = true;
        result["message"] = "Sandbox analysis started successfully";
        result["analysis_result"] = analysisResult;
        
        return result;
    } catch (const std::exception& e) {
        qDebug() << "Exception in analyzeFile:" << e.what();
        result["success"] = false;
        result["message"] = QString("Exception occurred: %1").arg(e.what());
        
        // Güvenli temizlik
        try {
            if (dockerManager && dockerManager->isContainerRunning()) {
                dockerManager->stopContainer();
            }
        } catch (...) {
            qDebug() << "Exception during container cleanup";
        }
        
        return result;
    } catch (...) {
        qDebug() << "Unknown exception in analyzeFile";
        result["success"] = false;
        result["message"] = "Unknown exception occurred";
        
        // Güvenli temizlik
        try {
            if (dockerManager && dockerManager->isContainerRunning()) {
                dockerManager->stopContainer();
            }
        } catch (...) {
            qDebug() << "Exception during container cleanup";
        }
        
        return result;
    }
}

QJsonObject SandboxManager::getAnalysisResults() {
    QJsonObject results;
    
    try {
        // Birleştirilmiş sonuçları oluştur
        results["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
        results["timeout"] = analysisTimeout;
        
        // Konteyner çalışıyor mu kontrol et
        if (!dockerManager || !dockerManager->isContainerRunning()) {
            results["error"] = "Container is not running";
            return results;
        }
        
        // Farklı aktivite türlerine göre sonuçları ekleyelim - güvenli şekilde
        QJsonObject filesystem = parseFileSystemActivity();
        if (!filesystem.isEmpty()) {
            results["filesystem"] = filesystem;
        } else {
            results["filesystem"] = QJsonObject{{"error", "Failed to parse filesystem activity"}};
        }
        
        QJsonObject network = parseNetworkActivity();
        if (!network.isEmpty()) {
            results["network"] = network;
        } else {
            results["network"] = QJsonObject{{"error", "Failed to parse network activity"}};
        }
        
        QJsonObject process = parseProcessActivity();
        if (!process.isEmpty()) {
            results["process"] = process;
        } else {
            results["process"] = QJsonObject{{"error", "Failed to parse process activity"}};
        }
        
        QJsonObject registry = parseRegistryActivity();
        if (!registry.isEmpty()) {
            results["registry"] = registry;
        } else {
            results["registry"] = QJsonObject{{"error", "Failed to parse registry activity"}};
        }
        
        // Basit bir dosya bilgisi analizi ekleyelim
        QString command = "find /samples -type f -exec file {} \\; | sort";
        QString fileInfo = dockerManager->executeCommand(command);
        if (!fileInfo.isEmpty()) {
            results["file_info"] = fileInfo;
        }
        
        // Temel dosya hash'leri
        command = "find /samples -type f -exec sha256sum {} \\; | sort";
        QString hashInfo = dockerManager->executeCommand(command);
        if (!hashInfo.isEmpty()) {
            results["hash_info"] = hashInfo;
        }
        
        // Tamamlandığında container'ı durdur
        dockerManager->stopContainer();
        
        return results;
    } catch (const std::exception& e) {
        qDebug() << "Exception in getAnalysisResults:" << e.what();
        results["error"] = QString("Exception occurred: %1").arg(e.what());
        
        // Güvenli temizlik
        try {
            if (dockerManager && dockerManager->isContainerRunning()) {
                dockerManager->stopContainer();
            }
        } catch (...) {
            qDebug() << "Exception during container cleanup";
        }
        
        return results;
    } catch (...) {
        qDebug() << "Unknown exception in getAnalysisResults";
        results["error"] = "Unknown exception occurred";
        
        // Güvenli temizlik
        try {
            if (dockerManager && dockerManager->isContainerRunning()) {
                dockerManager->stopContainer();
            }
        } catch (...) {
            qDebug() << "Exception during container cleanup";
        }
        
        return results;
    }
}

QJsonObject SandboxManager::parseFileSystemActivity() {
    QJsonObject fileSystemActivity;
    
    try {
        // Konteyner çalışıyor mu kontrol et
        if (!dockerManager || !dockerManager->isContainerRunning()) {
            return fileSystemActivity;
        }
        
        // Önce Cuckoo raporunun varlığını kontrol edelim
        QString checkCommand = "[ -f /cuckoo/storage/analyses/latest/reports/report.json ] && echo \"exists\" || echo \"missing\"";
        QString checkResult = dockerManager->executeCommand(checkCommand);
        
        if (!checkResult.contains("exists")) {
            qDebug() << "Cuckoo report file not found, using basic filesystem info";
            
            // Basit dosya sistemi bilgileri toplama
            QJsonArray accessedFiles;
            
            // Dosya sistemi aktivitelerini getir - basit alternatif
            QString findCommand = "find /samples -type f -exec ls -la {} \\; 2>/dev/null || echo \"No files found\"";
            QString findResult = dockerManager->executeCommand(findCommand);
            
            QStringList lines = findResult.split('\n');
            for (const QString& line : lines) {
                if (!line.trimmed().isEmpty() && !line.contains("No files found")) {
                    accessedFiles.append(line.trimmed());
                }
            }
            
            fileSystemActivity["accessed_files"] = accessedFiles;
            return fileSystemActivity;
        }
        
        // Dosya sistemi aktivitelerini getir - Cuckoo raporu
        QString command = "cat /cuckoo/storage/analyses/latest/reports/report.json | jq .behavior.summary.files 2>/dev/null || echo \"[]\"";
        QString result = dockerManager->executeCommand(command);
        
        if (result.isEmpty() || result.trimmed() == "[]") {
            qDebug() << "Empty file system activity or jq command not available";
            fileSystemActivity["accessed_files"] = QJsonArray();
            return fileSystemActivity;
        }
        
        QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8());
        if (!doc.isNull() && doc.isArray()) {
            fileSystemActivity["accessed_files"] = doc.array();
        } else {
            qDebug() << "Invalid JSON for file system activity:" << result;
            fileSystemActivity["accessed_files"] = QJsonArray();
            fileSystemActivity["parse_error"] = "Invalid JSON format";
        }
        
        // Tehlikeli dosya işlemleri
        fileSystemActivity["suspicious_writes"] = QJsonArray();
        fileSystemActivity["deleted_files"] = QJsonArray();
        
        return fileSystemActivity;
    } catch (const std::exception& e) {
        qDebug() << "Exception in parseFileSystemActivity:" << e.what();
        fileSystemActivity["error"] = QString("Exception: %1").arg(e.what());
        return fileSystemActivity;
    } catch (...) {
        qDebug() << "Unknown exception in parseFileSystemActivity";
        fileSystemActivity["error"] = "Unknown exception";
        return fileSystemActivity;
    }
}

QJsonObject SandboxManager::parseNetworkActivity() {
    QJsonObject networkActivity;
    
    try {
        // Konteyner çalışıyor mu kontrol et
        if (!dockerManager || !dockerManager->isContainerRunning()) {
            return networkActivity;
        }
        
        // Önce Cuckoo raporunun varlığını kontrol edelim
        QString checkCommand = "[ -f /cuckoo/storage/analyses/latest/reports/report.json ] && echo \"exists\" || echo \"missing\"";
        QString checkResult = dockerManager->executeCommand(checkCommand);
        
        if (!checkResult.contains("exists")) {
            qDebug() << "Cuckoo report file not found, using basic network info";
            
            // Basit ağ bilgileri toplama
            QString netstatCommand = "netstat -an 2>/dev/null || ss -tuln 2>/dev/null || echo \"Network commands not available\"";
            QString netstatResult = dockerManager->executeCommand(netstatCommand);
            
            if (netstatResult.contains("Network commands not available") || netstatResult.isEmpty()) {
                networkActivity["error"] = "No network info available";
            } else {
                networkActivity["connections"] = netstatResult;
            }
            
            return networkActivity;
        }
        
        // Ağ aktivitelerini getir - Cuckoo raporu
        QString command = "cat /cuckoo/storage/analyses/latest/reports/report.json | jq .network 2>/dev/null || echo \"{}\"";
        QString result = dockerManager->executeCommand(command);
        
        if (result.isEmpty() || result == "{}") {
            qDebug() << "Empty network activity or jq command not available";
            
            // Varsayılan boş yapılar
            networkActivity["dns_requests"] = QJsonArray();
            networkActivity["http_requests"] = QJsonArray();
            networkActivity["tcp_connections"] = QJsonArray();
            networkActivity["udp_connections"] = QJsonArray();
            return networkActivity;
        }
        
        QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8());
        if (!doc.isNull() && doc.isObject()) {
            networkActivity = doc.object();
        } else {
            qDebug() << "Invalid JSON for network activity:" << result;
            networkActivity["dns_requests"] = QJsonArray();
            networkActivity["http_requests"] = QJsonArray();
            networkActivity["tcp_connections"] = QJsonArray();
            networkActivity["udp_connections"] = QJsonArray();
            networkActivity["parse_error"] = "Invalid JSON format";
        }
        
        return networkActivity;
    } catch (const std::exception& e) {
        qDebug() << "Exception in parseNetworkActivity:" << e.what();
        networkActivity["error"] = QString("Exception: %1").arg(e.what());
        return networkActivity;
    } catch (...) {
        qDebug() << "Unknown exception in parseNetworkActivity";
        networkActivity["error"] = "Unknown exception";
        return networkActivity;
    }
}

QJsonObject SandboxManager::parseProcessActivity() {
    QJsonObject processActivity;
    
    try {
        // Konteyner çalışıyor mu kontrol et
        if (!dockerManager || !dockerManager->isContainerRunning()) {
            return processActivity;
        }
        
        // Önce Cuckoo raporunun varlığını kontrol edelim
        QString checkCommand = "[ -f /cuckoo/storage/analyses/latest/reports/report.json ] && echo \"exists\" || echo \"missing\"";
        QString checkResult = dockerManager->executeCommand(checkCommand);
        
        if (!checkResult.contains("exists")) {
            qDebug() << "Cuckoo report file not found, using basic process info";
            
            // Basit süreç bilgileri toplama
            QString psCommand = "ps -ef 2>/dev/null || ps aux 2>/dev/null || echo \"Process commands not available\"";
            QString psResult = dockerManager->executeCommand(psCommand);
            
            if (psResult.contains("Process commands not available") || psResult.isEmpty()) {
                processActivity["error"] = "No process info available";
            } else {
                QJsonArray processes;
                QStringList lines = psResult.split('\n');
                foreach (const QString &line, lines) {
                    if (!line.trimmed().isEmpty()) {
                        processes.append(line.trimmed());
                    }
                }
                processActivity["processes"] = processes;
            }
            
            return processActivity;
        }
        
        // İşlem aktivitelerini getir - Cuckoo raporu
        QString command = "cat /cuckoo/storage/analyses/latest/reports/report.json | jq .behavior.processes 2>/dev/null || echo \"[]\"";
        QString result = dockerManager->executeCommand(command);
        
        if (result.isEmpty() || result.trimmed() == "[]") {
            qDebug() << "Empty process activity or jq command not available";
            processActivity["processes"] = QJsonArray();
            return processActivity;
        }
        
        QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8());
        if (!doc.isNull() && doc.isArray()) {
            processActivity["processes"] = doc.array();
        } else {
            qDebug() << "Invalid JSON for process activity:" << result;
            processActivity["processes"] = QJsonArray();
            processActivity["parse_error"] = "Invalid JSON format";
        }
        
        return processActivity;
    } catch (const std::exception& e) {
        qDebug() << "Exception in parseProcessActivity:" << e.what();
        processActivity["error"] = QString("Exception: %1").arg(e.what());
        return processActivity;
    } catch (...) {
        qDebug() << "Unknown exception in parseProcessActivity";
        processActivity["error"] = "Unknown exception";
        return processActivity;
    }
}

QJsonObject SandboxManager::parseRegistryActivity() {
    QJsonObject registryActivity;
    
    try {
        // Konteyner çalışıyor mu kontrol et
        if (!dockerManager || !dockerManager->isContainerRunning()) {
            return registryActivity;
        }
        
        // Önce Cuckoo raporunun varlığını kontrol edelim
        QString checkCommand = "[ -f /cuckoo/storage/analyses/latest/reports/report.json ] && echo \"exists\" || echo \"missing\"";
        QString checkResult = dockerManager->executeCommand(checkCommand);
        
        if (!checkResult.contains("exists")) {
            qDebug() << "Cuckoo report file not found, registry info not available on non-Windows systems";
            
            // Linux sistemlerde registry yok, basit bir sistem bilgisi verelim
            QString sysInfoCommand = "uname -a 2>/dev/null || echo \"System info not available\"";
            QString sysInfoResult = dockerManager->executeCommand(sysInfoCommand);
            
            if (sysInfoResult.contains("System info not available") || sysInfoResult.isEmpty()) {
                registryActivity["error"] = "No registry applicable (non-Windows system)";
            } else {
                registryActivity["system_info"] = sysInfoResult;
                registryActivity["note"] = "Registry operations only available on Windows systems";
            }
            
            return registryActivity;
        }
        
        // Kayıt defteri aktivitelerini getir - Cuckoo raporu
        QString command = "cat /cuckoo/storage/analyses/latest/reports/report.json | jq .behavior.summary.keys 2>/dev/null || echo \"[]\"";
        QString result = dockerManager->executeCommand(command);
        
        if (result.isEmpty() || result.trimmed() == "[]") {
            qDebug() << "Empty registry activity or jq command not available";
            registryActivity["registry_keys"] = QJsonArray();
            return registryActivity;
        }
        
        QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8());
        if (!doc.isNull() && doc.isArray()) {
            registryActivity["registry_keys"] = doc.array();
        } else {
            qDebug() << "Invalid JSON for registry activity:" << result;
            registryActivity["registry_keys"] = QJsonArray();
            registryActivity["parse_error"] = "Invalid JSON format";
        }
        
        // Tehlikeli kayıt defteri işlemleri
        registryActivity["suspicious_registry_operations"] = QJsonArray();
        
        return registryActivity;
    } catch (const std::exception& e) {
        qDebug() << "Exception in parseRegistryActivity:" << e.what();
        registryActivity["error"] = QString("Exception: %1").arg(e.what());
        return registryActivity;
    } catch (...) {
        qDebug() << "Unknown exception in parseRegistryActivity";
        registryActivity["error"] = "Unknown exception";
        return registryActivity;
    }
}