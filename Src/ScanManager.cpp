#include "../Headers/ScanManager.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QApplication>

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
    m_dbManager(dbManager)
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
    if (m_refreshTimer->isActive()) {
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
    if (!m_resultTextEdit || !m_statusBar || !m_logTextEdit) {
        qDebug() << "UI components not initialized for offline scan";
        return;
    }
    
    // YaraRuleManager kontrolü
    if (!m_yaraManager) {
        qDebug() << "YARA manager is null";
        m_resultTextEdit->appendPlainText(tr("❌ Error: YARA scanner is not available"));
        m_statusBar->showMessage(tr("Scan failed: YARA scanner not available"));
        return;
    }
    
    // Durum mesajını güncelle
    m_statusBar->showMessage(tr("Scanning file: %1").arg(filePath));
    
    // Log'a ekle
    m_logTextEdit->appendPlainText(QString("\n🔍 %1 | Scanning file: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(filePath));
    
    // Sonuç alanını temizle ve ilk bilgiyi göster
    m_resultTextEdit->clear();
    m_resultTextEdit->appendPlainText(tr("Scanning file: %1\n").arg(filePath));
    m_resultTextEdit->appendPlainText(tr("Using YARA rules for offline scanning...\n"));
    
    // Dosya var mı kontrol et
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile() || !fileInfo.isReadable()) {
        m_resultTextEdit->appendPlainText(tr("❌ File not found or unreadable: %1").arg(filePath));
        m_statusBar->showMessage(tr("Scan failed: File not found"));
        return;
    }
    
    // YARA motoru ile offline tarama yap
    try {
        std::vector<std::string> matchesVector;
        std::error_code error = m_yaraManager->scanFile(filePath.toStdString(), matchesVector);
        
        // Convert std::vector<std::string> to QStringList
        QStringList matches;
        for (const auto& match : matchesVector) {
            matches.append(QString::fromStdString(match));
        }
        
        if (error) {
            m_resultTextEdit->appendPlainText(tr("❌ Error occurred during scanning: %1").arg(QString::fromStdString(error.message())));
        } else if (matches.isEmpty()) {
            m_resultTextEdit->appendPlainText(tr("✅ No threats detected in the file."));
        } else {
            m_resultTextEdit->appendPlainText(tr("⚠️ Potential threats detected in the file!\n"));
            m_resultTextEdit->appendPlainText(tr("Matching YARA rules:"));
            
            for (const QString &match : matches) {
                m_resultTextEdit->appendPlainText(tr("- %1").arg(match));
            }
            
            m_resultTextEdit->appendPlainText(tr("\n⚠️ This file may be harmful. Proceed with caution!"));
        }
        
        // İsteğe bağlı olarak, daha fazla analiz için VirusTotal'e yönlendirebiliriz
        if (!matches.isEmpty()) {
            m_resultTextEdit->appendPlainText(tr("\nFor more detailed analysis, you can use the 'VirusTotal Scan' feature."));
        }
    } catch (const std::exception& e) {
        m_resultTextEdit->appendPlainText(tr("❌ Unexpected error occurred during scanning: %1").arg(e.what()));
        m_logTextEdit->appendPlainText(QString("\n❌ %1 | Scan error: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(e.what()));
    } catch (...) {
        m_resultTextEdit->appendPlainText(tr("❌ Unknown error occurred during scanning."));
        m_logTextEdit->appendPlainText(QString("\n❌ %1 | Scan error: Unknown error")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
    }
    
    // Durum çubuğunu güncelle
    m_statusBar->showMessage(tr("Scan completed"));
}

void ScanManager::performOnlineScan(const QString& filePath)
{
    if (!m_resultTextEdit || !m_statusBar || !m_logTextEdit || !m_apiManager)
        return;
    
    // API Key kontrolü
    if (!m_apiManager->hasApiKey()) {
        m_logTextEdit->appendPlainText(QString("\n⚠️ %1 | API key not found")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
        QMessageBox::warning(nullptr, tr("API Key Required"), 
                           tr("VirusTotal scan requires an API key.\n"
                              "Please use the 'Set API Key' option first."));
        return;
    }
    
    // Durum mesajını güncelle
    m_statusBar->showMessage(tr("Sending file to VirusTotal: %1").arg(filePath));
    
    // API isteğinden önce temizle ve bilgi mesajı göster
    m_resultTextEdit->clear();
    m_resultTextEdit->appendPlainText(tr("Sending file to VirusTotal: %1").arg(filePath));
    m_resultTextEdit->appendPlainText(tr("This process may take some time depending on the file size..."));
    
    // Dosya içeriğini okumalı ve multipart form olarak göndermeli
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        m_resultTextEdit->appendPlainText(tr("\n❌ File could not be opened: %1").arg(filePath));
        m_logTextEdit->appendPlainText(QString("\n❌ %1 | File could not be opened: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(filePath));
        return;
    }
    
    // Dosya verilerini oku
    QByteArray fileData = file.readAll();
    file.close();
    
    if (fileData.isEmpty()) {
        m_resultTextEdit->appendPlainText(tr("\n❌ File is empty: %1").arg(filePath));
        return;
    }
    
    // Dosya adını al (yalnızca dosya adı, yolu olmadan)
    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();
    
    // VirusTotal'e dosyayı gönder
    m_apiManager->uploadFileToVirusTotal(filePath, fileName, fileData);
    
    m_logTextEdit->appendPlainText(QString("\n📤 %1 | Sending file to VirusTotal: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(filePath));
}

bool ScanManager::performCdrScan(const QString& filePath) {
    if (!m_cdrManager) {
        qDebug() << "CDR manager is not initialized";
        if (m_resultTextEdit) {
            m_resultTextEdit->clear();
            m_resultTextEdit->appendPlainText("⚠️ CDR manager could not be initialized! Docker setup should be checked.");
        }
        return false;
    }
    
    // İmaj seçilmiş mi kontrol et, seçilmemişse kullanıcıya imaj seçtir
    if (m_cdrManager->getCurrentImageName().isEmpty()) {
        if (m_resultTextEdit) {
            m_resultTextEdit->clear();
            m_resultTextEdit->appendPlainText("⚠️ No Docker image selected for CDR operation!");
            m_resultTextEdit->appendPlainText("\nPlease select one of the following images:");
            
            QStringList availableImages = m_cdrManager->getAvailableCdrImages();
            for (int i = 0; i < availableImages.size(); ++i) {
                m_resultTextEdit->appendPlainText(QString("  %1. %2").arg(i+1).arg(availableImages[i]));
            }
            
            m_resultTextEdit->appendPlainText("\nBefore restarting the operation, select an image from Settings > Docker Configuration menu.");
        }
        
        // Docker imaj seçimi isteyen sinyal emisyonu
        emit dockerImageSelectionRequired("CDR");
        
        // Add a log for debugging
        qDebug() << "Emitted dockerImageSelectionRequired signal for CDR";
        
        // Ensure the user interface is updated before returning
        QApplication::processEvents();
        return false;
    }
    
    if (m_resultTextEdit) {
        m_resultTextEdit->clear();
        m_resultTextEdit->appendPlainText("🔍 Starting CDR scan...");
        m_resultTextEdit->appendPlainText("📄 File: " + filePath);
        m_resultTextEdit->appendPlainText("🐳 Docker Image: " + m_cdrManager->getCurrentImageName());
        m_resultTextEdit->appendPlainText("\nOperation in progress, please wait...\n");
    }
    
    // CDR taraması işlemi
    bool success = m_cdrManager->processFile(filePath);
    
    if (success) {
        QString cleanedFilePath = m_cdrManager->getCleanedFilePath(filePath);
        
        if (m_resultTextEdit) {
            m_resultTextEdit->appendPlainText("\n✅ CDR scan completed!");
            m_resultTextEdit->appendPlainText("🔒 Cleaned file: " + cleanedFilePath);
        }
        
        if (m_statusBar) {
            m_statusBar->showMessage("CDR scan completed: " + cleanedFilePath);
        }
    }
    else {
        if (m_resultTextEdit) {
            m_resultTextEdit->appendPlainText("\n❌ CDR scan failed!");
            m_resultTextEdit->appendPlainText("An error occurred while processing the file.");
        }
        
        if (m_statusBar) {
            m_statusBar->showMessage("CDR scan failed!");
        }
    }
    
    return success;
}

bool ScanManager::performSandboxScan(const QString& filePath) {
    if (!m_sandboxManager) {
        qDebug() << "Sandbox manager is not initialized";
        if (m_resultTextEdit) {
            m_resultTextEdit->clear();
            m_resultTextEdit->appendPlainText("⚠️ Sandbox manager could not be initialized! Docker setup should be checked.");
        }
        return false;
    }
    
    // İmaj seçilmiş mi kontrol et, seçilmemişse kullanıcıya imaj seçtir
    if (m_sandboxManager->getCurrentImageName().isEmpty()) {
        if (m_resultTextEdit) {
            m_resultTextEdit->clear();
            m_resultTextEdit->appendPlainText("⚠️ No Docker image selected for Sandbox operation!");
            m_resultTextEdit->appendPlainText("\nPlease select one of the following images:");
            
            QStringList availableImages = m_sandboxManager->getAvailableSandboxImages();
            for (int i = 0; i < availableImages.size(); ++i) {
                m_resultTextEdit->appendPlainText(QString("  %1. %2").arg(i+1).arg(availableImages[i]));
            }
            
            m_resultTextEdit->appendPlainText("\nBefore restarting the operation, select an image from Settings > Docker Configuration menu.");
        }
        
        // İmaj seçimi isteyen sinyal emisyonu
        emit dockerImageSelectionRequired("Sandbox");
        
        // Add a log for debugging
        qDebug() << "Emitted dockerImageSelectionRequired signal for Sandbox";
        
        // Ensure the user interface is updated before returning
        QApplication::processEvents();
        return false;
    }
    
    if (m_resultTextEdit) {
        m_resultTextEdit->clear();
        m_resultTextEdit->appendPlainText("🧪 Starting Sandbox analysis...");
        m_resultTextEdit->appendPlainText("📄 File: " + filePath);
        m_resultTextEdit->appendPlainText("🐳 Docker Image: " + m_sandboxManager->getCurrentImageName());
        m_resultTextEdit->appendPlainText("\nAnalysis in progress, please wait...\n");
    }

    // Sandbox analizi başlat ve sonuç objesini al
    QJsonObject analysisResult = m_sandboxManager->analyzeFile(filePath);
    bool success = analysisResult.value("success").toBool();
    
    if (success) {
        QJsonObject results = m_sandboxManager->getAnalysisResults();
        QString analysisResultJson = QString::fromUtf8(QJsonDocument(results).toJson(QJsonDocument::Indented));
        m_resultTextEdit->appendPlainText(tr("\n✅ Sandbox analysis completed."));
        m_resultTextEdit->appendPlainText(tr("\nANALYSIS RESULTS:"));
        m_resultTextEdit->appendPlainText(analysisResultJson);
        
        m_logTextEdit->appendPlainText(QString("\n✅ %1 | Sandbox analysis completed: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(filePath));
    } else {
        m_resultTextEdit->appendPlainText(tr("\n❌ Sandbox analysis failed."));
        m_logTextEdit->appendPlainText(QString("\n❌ %1 | Sandbox analysis failed: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(filePath));
    }
    
    // Durum çubuğunu güncelle
    m_statusBar->showMessage(tr("Sandbox analysis completed"));
    
    return success;
}

void ScanManager::handleApiResponse(const QJsonObject& response)
{
    // ...  (Mevcut implementasyon aynı kalabilir)
}

void ScanManager::handleApiError(const QString& errorMessage)
{
    // ...  (Mevcut implementasyon aynı kalabilir)
}

void ScanManager::fetchAnalysisResults(const QString& analysisId)
{
    // ...  (Mevcut implementasyon aynı kalabilir)
}

void ScanManager::checkAnalysisStatus()
{
    // ...  (Mevcut implementasyon aynı kalabilir)
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
    return m_cdrManager ? m_cdrManager->getAvailableCdrImages() : QStringList();
}

QStringList ScanManager::getAvailableSandboxImages() const {
    return m_sandboxManager ? m_sandboxManager->getAvailableSandboxImages() : QStringList();
}