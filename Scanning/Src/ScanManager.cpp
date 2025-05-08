#include "../Headers/ScanManager.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QApplication>
#include <QtConcurrent>
#include <QFile>
#include <QFileInfo>
#include <QThreadPool>

ScanManager::ScanManager(
    IApiManager* apiManager,
    IYaraRuleManager* yaraManager,
    ICdrManager* cdrManager,
    ISandboxManager* sandboxManager,
    IDbManager* dbManager,
    QObject *parent
) : QObject(parent),
    m_resultTextEdit(nullptr),
    m_logTextEdit(nullptr),
    m_statusBar(nullptr),
    m_refreshAttempts(0),
    m_apiManager(apiManager),
    m_yaraManager(yaraManager),
    m_cdrManager(cdrManager),
    m_sandboxManager(sandboxManager),
    m_dbManager(dbManager),
    m_operationInProgress(false)
{
    // Null kontrolü - güvenlik için
    if (!m_apiManager || !m_yaraManager || !m_cdrManager || !m_sandboxManager || !m_dbManager) {
        qCritical() << "ScanManager: One or more required components are null!";
    }
    
    // ApiManager sinyalleri - QObject üzerinden dinleniyor
    if (auto apiManager = dynamic_cast<QObject*>(m_apiManager)) {
        connect(apiManager, SIGNAL(responseReceived(const QJsonObject&)),
                this, SLOT(handleApiResponse(const QJsonObject&)));
        connect(apiManager, SIGNAL(error(const QString&)),
                this, SLOT(handleApiError(const QString&)));
    } else {
        qWarning() << "ScanManager: API Manager does not support signal/slot connections!";
    }
    
    // Yenileme zamanlayıcısını başlat
    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(10000); // 10 saniye aralıklarla kontrol et
    connect(m_refreshTimer, &QTimer::timeout, this, &ScanManager::checkAnalysisStatus);
}

ScanManager::~ScanManager()
{
    // Zamanlayıcıyı durdur
    if (m_refreshTimer && m_refreshTimer->isActive()) {
        m_refreshTimer->stop();
    }
    
    // Not: Dışarıdan enjekte edilen nesneleri burada silmiyoruz
    // onların sahipliği bu sınıfın dışında
}

void ScanManager::setTextEdit(QPlainTextEdit* resultTextEdit)
{
    m_resultTextEdit = resultTextEdit;
}

void ScanManager::setLogTextEdit(QPlainTextEdit* logTextEdit)
{
    m_logTextEdit = logTextEdit;
}

void ScanManager::setStatusBar(QStatusBar* statusBar)
{
    m_statusBar = statusBar;
}

void ScanManager::performOfflineScan(const QString& filePath)
{
    if (!m_yaraManager) {
        emit scanError("YARA yöneticisi başlatılmadı");
        return;
    }

    updateUiForOperationStart("Offline Scan", filePath);
    
    // İlerleme sinyali gönder - %10
    emit scanProgressUpdated(10);
    
    // İşlemi ayrı bir thread'de çalıştır
    QFuture<void> future = QtConcurrent::run([this, filePath]() {
        try {
            // İlerleme sinyali gönder - %30
            emit scanProgressUpdated(30);
            
            // YARA taraması için eşleşmeleri tutacak vektör
            std::vector<std::string> matches;
            
            // YARA taraması gerçekleştir
            auto ec = m_yaraManager->scanFile(filePath.toStdString(), matches);
            
            if (ec) {
                throw std::runtime_error("YARA tarama hatası: " + ec.message());
            }
            
            // İlerleme sinyali gönder - %70
            emit scanProgressUpdated(70);
            
            // Sonuçları formatla
            QString detailedResult;
            bool isClean = true;
            
            for (const auto& match : matches) {
                if (!detailedResult.isEmpty()) {
                    detailedResult += "<br/>";
                }
                detailedResult += QString("Rule: <b>%1</b>").arg(QString::fromStdString(match));
                
                // Herhangi bir kural eşleşmesi, dosyanın temiz olmadığı anlamına gelir
                isClean = false;
            }
            
            // Sonuç boşsa, dosya temizdir
            if (detailedResult.isEmpty()) {
                detailedResult = "No malicious patterns detected";
            }
            
            // İlerleme sinyali gönder - %90
            emit scanProgressUpdated(90);
            
            // Sonucu veritabanına kaydet
            logScanResult("Offline Scan", filePath, detailedResult, isClean);
            
            // İlerleme sinyali gönder - %100
            emit scanProgressUpdated(100);
            
            // Tarama tamamlandı sinyalini gönder
            emit scanCompleted("Offline Scan", filePath, detailedResult, isClean);
            
            // UI güncellemeleri
            updateUiForOperationComplete("Offline Scan", true, detailedResult);
        }
        catch (const std::exception& e) {
            QString errorMsg = QString("Offline tarama sırasında hata: %1").arg(e.what());
            emit scanError(errorMsg);
            updateUiForOperationComplete("Offline Scan", false, errorMsg);
        }
    });
}

void ScanManager::performOnlineScan(const QString& filePath) 
{
    if (!m_apiManager) {
        emit scanError("API yöneticisi başlatılmadı");
        return;
    }
    
    updateUiForOperationStart("VirusTotal Scan", filePath);
    
    // İlerleme sinyali gönder - %10
    emit scanProgressUpdated(10);
    
    // Dosyayı VirusTotal'a gönder
    m_currentAnalysisId.clear();
    m_refreshAttempts = 0;
    
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        QString errorMsg = QString("Geçersiz dosya: %1").arg(filePath);
        emit scanError(errorMsg);
        updateUiForOperationComplete("VirusTotal Scan", false, errorMsg);
        return;
    }
    
    // İlerleme sinyali gönder - %20
    emit scanProgressUpdated(20);
    
    // Dosyayı yükle
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QString errorMsg = QString("Dosya açılamadı: %1").arg(filePath);
        emit scanError(errorMsg);
        updateUiForOperationComplete("VirusTotal Scan", false, errorMsg);
        return;
    }
    
    QByteArray fileData = file.readAll();
    file.close();
    
    // VirusTotal'a dosyayı gönder
    m_apiManager->uploadFileToVirusTotal(filePath, fileInfo.fileName(), fileData);
    
    // İlerleme sinyali gönder - %40
    emit scanProgressUpdated(40);
    
    // VirusTotal sonuçlarını periyodik olarak kontrol etmek için timer'ı başlat
    if (!m_refreshTimer) {
        m_refreshTimer = new QTimer(this);
        connect(m_refreshTimer, &QTimer::timeout, this, &ScanManager::checkAnalysisStatus);
    }
    
    if (!m_refreshTimer->isActive()) {
        m_refreshTimer->start(5000); // 5 saniyede bir kontrol et
    }
}

void ScanManager::handleApiResponse(const QJsonObject& response)
{
    // İlerleme sinyali gönder - %60
    emit scanProgressUpdated(60);
    
    if (response.contains("id")) {
        m_currentAnalysisId = response["id"].toString();
        if (m_resultTextEdit) {
            m_resultTextEdit->appendPlainText(QString("Analiz ID: %1").arg(m_currentAnalysisId));
            m_resultTextEdit->appendPlainText("Analiz sonuçları bekleniyor...");
        }
    }
    else if (response.contains("data") && response["data"].isObject()) {
        // VirusTotal sonuçlarını işle
        QJsonObject data = response["data"].toObject();
        QJsonObject attributes = data["attributes"].toObject();
        
        // İlerleme sinyali gönder - %80
        emit scanProgressUpdated(80);
        
        QString filePath = attributes.contains("name") ? attributes["name"].toString() : "Unknown file";
        QJsonObject stats = attributes["stats"].toObject();
        int malicious = stats["malicious"].toInt();
        int suspicious = stats["suspicious"].toInt();
        int undetected = stats["undetected"].toInt();
        int total = malicious + suspicious + undetected;
        
        bool isClean = (malicious == 0 && suspicious == 0);
        
        // Detaylı sonuç metni oluştur
        QString detailedResult = QString("VirusTotal Results - Malicious: %1, Suspicious: %2, Undetected: %3, Total: %4")
                                     .arg(malicious).arg(suspicious).arg(undetected).arg(total);
        
        // İlerleme sinyali gönder - %100
        emit scanProgressUpdated(100);
        
        // Tarama tamamlandı sinyalini gönder
        emit scanCompleted("VirusTotal Scan", filePath, detailedResult, isClean);
        
        // Timer'ı durdur
        m_refreshTimer->stop();
        m_refreshAttempts = 0;
        
        // UI güncellemesi
        updateUiForOperationComplete("VirusTotal Scan", true, detailedResult);
        
        // Sonuçları veritabanına kaydet
        logScanResult("VirusTotal Scan", filePath, detailedResult, isClean);
    }
}

void ScanManager::handleApiError(const QString& errorMessage)
{
    emit scanError(QString("API hatası: %1").arg(errorMessage));
    updateUiForOperationComplete("VirusTotal Scan", false, errorMessage);
    
    // Timer'ı durdur
    if (m_refreshTimer && m_refreshTimer->isActive()) {
        m_refreshTimer->stop();
    }
}

bool ScanManager::performCdrScan(const QString& filePath, bool async)
{
    if (!m_cdrManager) {
        emit scanError("CDR yöneticisi başlatılmadı");
        return false;
    }
    
    if (!async) {
        // Senkron işlem - doğrudan çalıştır
        updateUiForOperationStart("CDR Process", filePath);
        emit scanProgressUpdated(10);
        
        try {
            // CDR işlemini gerçekleştir
            emit scanProgressUpdated(30);
            
            // Dosyayı işle ve temiz kopya oluştur - arayüz uyumlu
            bool success = m_cdrManager->processFile(filePath);
            
            if (!success) {
                throw std::runtime_error("CDR işlemi başarısız");
            }
            
            emit scanProgressUpdated(70);
            
            // Temizlenmiş dosya yolu
            QString outputPath = m_cdrManager->getCleanedFilePath(filePath);
            
            // Sonuç metni
            QString resultText = QString("File successfully processed. Output saved to: %1")
                                     .arg(outputPath);
            
            // İlerleme sinyali gönder - %100
            emit scanProgressUpdated(100);
            
            // Tarama tamamlandı sinyalini gönder
            emit scanCompleted("CDR Process", filePath, resultText, true);
            
            updateUiForOperationComplete("CDR Process", true, resultText);
            
            // Log kaydet
            logScanResult("CDR Process", filePath, resultText, true);
            return true;
        }
        catch (const std::exception& e) {
            QString errorMsg = QString("CDR işlemi sırasında hata: %1").arg(e.what());
            emit scanError(errorMsg);
            updateUiForOperationComplete("CDR Process", false, errorMsg);
            return false;
        }
    }
    else {
        // Asenkron işlem
        executeCdrScanAsync(filePath);
        return true;
    }
}

void ScanManager::executeCdrScanAsync(const QString& filePath)
{
    // İşlemi başlat
    updateUiForOperationStart("CDR Process", filePath);
    
    // İlerleme sinyali gönder - %10
    emit scanProgressUpdated(10);
    
    // İşlemi ayrı bir thread'de çalıştır
    QFuture<void> future = QtConcurrent::run([this, filePath]() {
        try {
            // CDR işlemini gerçekleştir
            emit scanProgressUpdated(30);
            
            // Dosyayı işle ve temiz kopya oluştur - arayüz uyumlu
            bool success = m_cdrManager->processFile(filePath);
            
            if (!success) {
                throw std::runtime_error("CDR işlemi başarısız");
            }
            
            emit scanProgressUpdated(70);
            
            // Temizlenmiş dosya yolu
            QString outputPath = m_cdrManager->getCleanedFilePath(filePath);
            
            // Sonuç metni
            QString resultText = QString("File successfully processed. Output saved to: %1")
                                     .arg(outputPath);
            
            // İlerleme sinyali gönder - %100
            emit scanProgressUpdated(100);
            
            // Tarama tamamlandı sinyalini gönder
            emit scanCompleted("CDR Process", filePath, resultText, true);
            
            // UI güncellemeleri
            updateUiForOperationComplete("CDR Process", true, resultText);
            
            // Log kaydet
            logScanResult("CDR Process", filePath, resultText, true);
        }
        catch (const std::exception& e) {
            QString errorMsg = QString("CDR işlemi sırasında hata: %1").arg(e.what());
            emit scanError(errorMsg);
            updateUiForOperationComplete("CDR Process", false, errorMsg);
        }
    });
}

bool ScanManager::performSandboxScan(const QString& filePath, bool async)
{
    if (!m_sandboxManager) {
        emit scanError("Sandbox yöneticisi başlatılmadı");
        return false;
    }
    
    if (!async) {
        // Senkron işlem - doğrudan çalıştır
        updateUiForOperationStart("Sandbox Analysis", filePath);
        emit scanProgressUpdated(10);
        
        try {
            // Sandbox analizi gerçekleştir
            emit scanProgressUpdated(30);
            
            // Dosyayı sandbox'ta analiz et - arayüz uyumlu
            QJsonObject analysisResults = m_sandboxManager->analyzeFile(filePath);
            
            emit scanProgressUpdated(70);
            
            // JSON'u string'e çevir
            QJsonDocument doc(analysisResults);
            QString report = doc.toJson(QJsonDocument::Indented);
            
            // Raporu işle
            bool isClean = !report.contains("SUSPICIOUS") && !report.contains("MALICIOUS");
            
            // İlerleme sinyali gönder - %100
            emit scanProgressUpdated(100);
            
            // Tarama tamamlandı sinyalini gönder
            emit scanCompleted("Sandbox Analysis", filePath, report, isClean);
            
            updateUiForOperationComplete("Sandbox Analysis", true, report);
            
            // Log kaydet
            logScanResult("Sandbox Analysis", filePath, report, isClean);
            return true;
        }
        catch (const std::exception& e) {
            QString errorMsg = QString("Sandbox analizi sırasında hata: %1").arg(e.what());
            emit scanError(errorMsg);
            updateUiForOperationComplete("Sandbox Analysis", false, errorMsg);
            return false;
        }
    }
    else {
        // Asenkron işlem
        executeSandboxScanAsync(filePath);
        return true;
    }
}

void ScanManager::executeSandboxScanAsync(const QString& filePath)
{
    // İşlemi başlat
    updateUiForOperationStart("Sandbox Analysis", filePath);
    
    // İlerleme sinyali gönder - %10
    emit scanProgressUpdated(10);
    
    // İşlemi ayrı bir thread'de çalıştır
    QFuture<void> future = QtConcurrent::run([this, filePath]() {
        try {
            // Sandbox analizi gerçekleştir
            emit scanProgressUpdated(30);
            
            // Dosyayı sandbox'ta analiz et - arayüz uyumlu
            QJsonObject analysisResults = m_sandboxManager->analyzeFile(filePath);
            
            emit scanProgressUpdated(70);
            
            // JSON'u string'e çevir
            QJsonDocument doc(analysisResults);
            QString report = doc.toJson(QJsonDocument::Indented);
            
            // Raporu işle
            bool isClean = !report.contains("SUSPICIOUS") && !report.contains("MALICIOUS");
            
            // İlerleme sinyali gönder - %100
            emit scanProgressUpdated(100);
            
            // Tarama tamamlandı sinyalini gönder
            emit scanCompleted("Sandbox Analysis", filePath, report, isClean);
            
            // UI güncellemeleri
            updateUiForOperationComplete("Sandbox Analysis", true, report);
            
            // Log kaydet
            logScanResult("Sandbox Analysis", filePath, report, isClean);
        }
        catch (const std::exception& e) {
            QString errorMsg = QString("Sandbox analizi sırasında hata: %1").arg(e.what());
            emit scanError(errorMsg);
            updateUiForOperationComplete("Sandbox Analysis", false, errorMsg);
        }
    });
}

void ScanManager::updateUiForOperationStart(const QString& operationType, const QString& filePath) {
    if (m_resultTextEdit) {
        m_resultTextEdit->clear();
        
        if (operationType == "CDR Scan") {
            m_resultTextEdit->appendPlainText("🔍 Starting CDR scan...");
            m_resultTextEdit->appendPlainText("📄 File: " + filePath);
            m_resultTextEdit->appendPlainText("🐳 Docker Image: " + m_cdrManager->getCurrentImageName());
        } else if (operationType == "Sandbox Scan") {
            m_resultTextEdit->appendPlainText("🧪 Starting Sandbox analysis...");
            m_resultTextEdit->appendPlainText("📄 File: " + filePath);
            m_resultTextEdit->appendPlainText("🐳 Docker Image: " + m_sandboxManager->getCurrentImageName());
        } else if (operationType == "Offline Scan") {
            m_resultTextEdit->appendPlainText("🔍 Starting Offline scan...");
            m_resultTextEdit->appendPlainText("📄 File: " + filePath);
        } else if (operationType == "VirusTotal Scan") {
            m_resultTextEdit->appendPlainText("🌐 Starting VirusTotal scan...");
            m_resultTextEdit->appendPlainText("📄 File: " + filePath);
        }
        
        m_resultTextEdit->appendPlainText("\nOperation in progress, please wait...\n");
    }
    
    if (m_statusBar) {
        m_statusBar->showMessage(tr("%1 in progress...").arg(operationType));
    }
}

void ScanManager::updateUiForOperationComplete(const QString& operationType, bool success, const QString& details) {
    if (m_resultTextEdit) {
        if (success) {
            m_resultTextEdit->appendPlainText(QString("\n✅ %1 completed!").arg(operationType));
            
            if (!details.isEmpty()) {
                if (operationType == "CDR Scan") {
                    m_resultTextEdit->appendPlainText("🔒 Cleaned file: " + details);
                } else {
                    m_resultTextEdit->appendPlainText(details);
                }
            }
        } else {
            m_resultTextEdit->appendPlainText(QString("\n❌ %1 failed!").arg(operationType));
            m_resultTextEdit->appendPlainText("An error occurred during the operation.");
        }
    }
    
    if (m_statusBar) {
        if (success) {
            m_statusBar->showMessage(tr("%1 completed successfully").arg(operationType));
        } else {
            m_statusBar->showMessage(tr("%1 failed").arg(operationType));
        }
    }
}

void ScanManager::logScanResult(const QString& scanType, const QString& filePath, const QString& result, bool isClean)
{
    // Eğer veritabanı yöneticisi ayarlanmadıysa çık
    if (!m_dbManager) {
        qWarning() << "Database manager is not initialized, scan result not logged";
        return;
    }
    
    try {
        // Güncel zamanı al
        QDateTime now = QDateTime::currentDateTime();
        
        // Sonucu veritabanına kaydetmek için uygun bir şekilde logla
        // Not: IDbManager sınıfında insertScanResult metodu olmadığı için
        // doğrudan kayıt yapamıyoruz, sadece logluyoruz
        if (m_logTextEdit) {
            m_logTextEdit->appendPlainText(QString("[%1] %2 - %3 - %4")
                .arg(now.toString("yyyy-MM-dd hh:mm:ss"))
                .arg(scanType)
                .arg(filePath)
                .arg(isClean ? "Clean" : "Suspicious/Malicious"));
        }
    }
    catch (const std::exception& e) {
        qWarning() << "Exception while logging scan result:" << e.what();
    }
}

void ScanManager::fetchAnalysisResults(const QString& analysisId)
{
    // ... (Mevcut implementasyonu koru)
}

void ScanManager::checkAnalysisStatus()
{
    // ... (Mevcut implementasyonu koru)
}

bool ScanManager::isCdrInitialized() const
{
    if (!m_cdrManager)
        return false;
    
    return m_cdrManager->initialize();
}

bool ScanManager::isSandboxInitialized() const
{
    if (!m_sandboxManager)
        return false;
    
    return m_sandboxManager->initialize();
}

bool ScanManager::isDbInitialized() const
{
    if (!m_dbManager)
        return false;
    
    return m_dbManager->isDatabaseConnected();
}

// Delegasyon metotları
void ScanManager::setCdrImageName(const QString& imageName) {
    if (m_cdrManager) {
        m_cdrManager->setCdrImageName(imageName);
    }
}

void ScanManager::setSandboxImageName(const QString& imageName) {
    if (m_sandboxManager) {
        m_sandboxManager->setSandboxImageName(imageName);
    }
}

QString ScanManager::getCurrentCdrImageName() const {
    return m_cdrManager ? m_cdrManager->getCurrentImageName() : QString();
}

QString ScanManager::getCurrentSandboxImageName() const {
    return m_sandboxManager ? m_sandboxManager->getCurrentImageName() : QString();
}

QStringList ScanManager::getAvailableCdrImages() const {
    if (m_cdrManager) {
        return m_cdrManager->getAvailableCdrImages();
    }
    return QStringList();
}

QStringList ScanManager::getAvailableSandboxImages() const {
    if (m_sandboxManager) {
        return m_sandboxManager->getAvailableSandboxImages();
    }
    return QStringList();
}