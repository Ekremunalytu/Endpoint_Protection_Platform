#include "../Headers/ScanManager.h"
#include "../Headers/ApiManager.h"
#include "../Headers/YaraRuleManager.h"
#include "../Headers/CdrManager.h"
#include "../Headers/SandboxManager.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QApplication>  // Add this line to include QApplication

ScanManager::ScanManager(QObject *parent)
    : QObject(parent),
      m_resultTextEdit(nullptr),
      m_logTextEdit(nullptr),
      m_statusBar(nullptr),
      m_refreshAttempts(0)
{
    // Manager nesnelerini oluştur
    m_apiManager = ApiManager::getInstance();
    m_yaraManager = new YaraRuleManager();
    m_cdrManager = new CdrManager(this);
    m_sandboxManager = new SandboxManager(this);
    
    // Connect to ApiManager signals
    connect(m_apiManager, &ApiManager::responseReceived, this, &ScanManager::handleApiResponse);
    connect(m_apiManager, &ApiManager::error, this, &ScanManager::handleApiError);
    
    // Initialize refresh timer
    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(10000); // 10 saniye aralıklarla kontrol et
    connect(m_refreshTimer, &QTimer::timeout, this, &ScanManager::checkAnalysisStatus);
    
    // YARA başlatma ve kuralları yükleme
    std::error_code error = m_yaraManager->initialize();
    if (error) {
        qDebug() << "YARA initialization error:" << QString::fromStdString(error.message());
    } else {
        qDebug() << "YARA successfully initialized.";
        
        // Kuralları yükle
        QString rulePath = QCoreApplication::applicationDirPath() + "/Rules/test.yar";
        error = m_yaraManager->loadRules(rulePath.toStdString());
        if (error) {
            qDebug() << "Error loading YARA rules:" << QString::fromStdString(error.message());
        } else {
            qDebug() << "YARA rules successfully loaded.";
        }
    }
}

ScanManager::~ScanManager()
{
    // Stop timer if running
    if (m_refreshTimer->isActive()) {
        m_refreshTimer->stop();
    }
    delete m_refreshTimer;
    
    if (m_yaraManager) delete m_yaraManager;
    // Not: ApiManager singleton olduğu için ve diğer manager'lar parent'a sahip olduğu için
    // onları burada silmeye gerek yok.
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
    
    // YaraRuleManager'ın null olup olmadığını kontrol et
    if (!m_yaraManager) {
        qDebug() << "YARA manager is null, creating a new instance";
        m_yaraManager = new YaraRuleManager();
        
        // YARA başlatma ve kuralları yükleme
        std::error_code error = m_yaraManager->initialize();
        if (error) {
            m_resultTextEdit->appendPlainText(tr("❌ YARA initialization error: %1").arg(QString::fromStdString(error.message())));
            m_statusBar->showMessage(tr("Scan failed: YARA could not be initialized"));
            return;
        }
        
        // Kuralları yükle
        QString rulePath = QCoreApplication::applicationDirPath() + "/Rules/test.yar";
        error = m_yaraManager->loadRules(rulePath.toStdString());
        if (error) {
            m_resultTextEdit->appendPlainText(tr("❌ Error loading YARA rules: %1").arg(QString::fromStdString(error.message())));
            m_statusBar->showMessage(tr("Scan failed: YARA rules could not be loaded"));
            return;
        }
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
    if (!m_resultTextEdit || !m_statusBar || !m_logTextEdit)
        return;
    
    // API Key kontrolü
    if (m_apiManager->getApiKey().isEmpty()) {
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
        
        // Make sure this signal is actually connected to a slot that shows the selection UI
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
        
        // Make sure this signal is actually connected to a slot that shows the selection UI
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
    if (!m_resultTextEdit || !m_statusBar)
        return;
    
    // Analyze response type
    if (response.contains("data")) {
        QJsonObject data = response["data"].toObject();
        QString type = data["type"].toString();
        
        // Case 1: Analysis result
        if (type == "analysis") {
            // This could be either an initial file upload response or a result of fetchAnalysisResults
            QString analysisId = data["id"].toString();
            
            // Store the current analysis ID for auto-refresh
            m_currentAnalysisId = analysisId;
            
            // Check if this is a complete analysis result with attributes
            if (data.contains("attributes")) {
                QJsonObject attributes = data["attributes"].toObject();
                QString status = attributes.contains("status") ? attributes["status"].toString() : "";
                
                // Handle different analysis statuses
                if (status == "queued" || status == "in-progress") {
                    // Analysis is still in queue or in progress, start/continue auto-refresh timer
                    if (!m_refreshTimer->isActive()) {
                        m_refreshTimer->start();
                        m_refreshAttempts = 0;
                        
                        if (m_logTextEdit) {
                            m_logTextEdit->appendPlainText(QString("\n⏳ %1 | Analysis in %2 status, auto-refresh started: %3")
                                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                                .arg(status)
                                .arg(analysisId));
                        }
                    }
                    
                    // Update UI to show waiting status if results are empty
                    if (attributes.contains("results") && attributes["results"].toObject().isEmpty()) {
                        if (!status.isEmpty()) {
                            // Only update the UI if the number of attempts is within limits or at milestone attempts
                            if (m_refreshAttempts == 0 || m_refreshAttempts % 3 == 0 || m_refreshAttempts == MAX_REFRESH_ATTEMPTS - 1) {
                                m_resultTextEdit->appendPlainText(tr("\n⏳ Analysis status: %1 (Attempt %2/%3)")
                                    .arg(status)
                                    .arg(m_refreshAttempts + 1)
                                    .arg(MAX_REFRESH_ATTEMPTS));
                                m_resultTextEdit->appendPlainText(tr("Results are not ready yet. Will refresh automatically..."));
                            }
                            
                            // Check if we've reached the maximum number of attempts
                            if (m_refreshAttempts >= MAX_REFRESH_ATTEMPTS - 1) {
                                // Stop the timer to prevent further attempts
                                m_refreshTimer->stop();
                                m_resultTextEdit->appendPlainText(tr("\n⚠️ Maximum wait time exceeded for analysis results."));
                                m_resultTextEdit->appendPlainText(tr("Analysis may still be ongoing. You can try again later or use the link below:"));
                                
                                // Add link to VirusTotal
                                if (data.contains("links") && data["links"].toObject().contains("self")) {
                                    QString selfLink = data["links"].toObject()["self"].toString();
                                    QString vtGuiLink = selfLink.replace("api/v3/", "gui/");
                                    m_resultTextEdit->appendPlainText(vtGuiLink);
                                } else {
                                    m_resultTextEdit->appendPlainText(tr("https://www.virustotal.com/gui/analyses/%1").arg(m_currentAnalysisId));
                                }
                                
                                // Log the maximum attempts reached
                                if (m_logTextEdit) {
                                    m_logTextEdit->appendPlainText(QString("\n⚠️ %1 | Maximum wait time exceeded (%2 attempts), analysis results not obtained")
                                        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                                        .arg(MAX_REFRESH_ATTEMPTS));
                                }
                                
                                // Clear the current analysis ID to prevent further lookups
                                m_currentAnalysisId.clear();
                                m_refreshAttempts = 0;
                            }
                            
                            m_statusBar->showMessage(tr("VirusTotal analysis ongoing (%1)...").arg(status));
                        }
                    }
                } 
                else if (status == "completed") {
                    // Analysis is complete, stop auto-refresh timer
                    if (m_refreshTimer->isActive()) {
                        m_refreshTimer->stop();
                        m_refreshAttempts = 0;
                        
                        if (m_logTextEdit) {
                            m_logTextEdit->appendPlainText(QString("\n✅ %1 | Analysis completed, auto-refresh stopped: %2")
                                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                                .arg(analysisId));
                        }
                    }
                    
                    // Process completed analysis results
                    if (attributes.contains("stats")) {
                        QJsonObject stats = attributes["stats"].toObject();
                        
                        int malicious = stats["malicious"].toInt();
                        int suspicious = stats["suspicious"].toInt();
                        int undetected = stats["undetected"].toInt();
                        int timeout = stats["timeout"].toInt();
                        int total = malicious + suspicious + undetected + timeout;
                        
                        // Display detailed results
                        m_resultTextEdit->clear();
                        m_resultTextEdit->appendPlainText(tr("VirusTotal Analysis Results:"));
                        m_resultTextEdit->appendPlainText(tr("--------------------------------------"));
                        m_resultTextEdit->appendPlainText(tr("📋 Analysis ID: %1").arg(analysisId));
                        
                        // Format date if available
                        if (attributes.contains("date")) {
                            QDateTime analysisDate = QDateTime::fromSecsSinceEpoch(attributes["date"].toInt());
                            m_resultTextEdit->appendPlainText(tr("📅 Analysis Date: %1").arg(
                                analysisDate.toString("yyyy-MM-dd hh:mm:ss")
                            ));
                        }
                        
                        // Display scan statistics
                        m_resultTextEdit->appendPlainText(tr("\n📊 Scan Summary:"));
                        m_resultTextEdit->appendPlainText(tr("  🔴 Malicious: %1").arg(malicious));
                        m_resultTextEdit->appendPlainText(tr("  🟠 Suspicious: %1").arg(suspicious));
                        m_resultTextEdit->appendPlainText(tr("  🟢 Clean: %1").arg(undetected));
                        m_resultTextEdit->appendPlainText(tr("  ⚪ Timeout: %1").arg(timeout));
                        m_resultTextEdit->appendPlainText(tr("  📈 Total: %1").arg(total));
                        
                        // Risk assessment
                        QString risk;
                        if (malicious > 0) {
                            risk = tr("🔴 HIGH RISK - %1 antivirus engines detected this file as malicious!").arg(malicious);
                        } else if (suspicious > 0) {
                            risk = tr("🟠 MEDIUM RISK - %1 antivirus engines flagged this file as suspicious.").arg(suspicious);
                        } else {
                            risk = tr("🟢 LOW RISK - No antivirus engines detected this file as malicious.");
                        }
                        
                        m_resultTextEdit->appendPlainText(tr("\n⚠️ Risk Assessment:"));
                        m_resultTextEdit->appendPlainText(risk);
                        
                        // Get file information
                        QJsonObject fileInfo;
                        if (response.contains("meta") && response["meta"].toObject().contains("file_info")) {
                            fileInfo = response["meta"].toObject()["file_info"].toObject();
                        } else if (attributes.contains("meta") && attributes["meta"].toObject().contains("file_info")) {
                            fileInfo = attributes["meta"].toObject()["file_info"].toObject();
                        }
                        
                        // Display file info if available
                        if (!fileInfo.isEmpty()) {
                            m_resultTextEdit->appendPlainText(tr("\n📄 File Information:"));
                            if (fileInfo.contains("sha256"))
                                m_resultTextEdit->appendPlainText(tr("  SHA-256: %1").arg(fileInfo["sha256"].toString()));
                            if (fileInfo.contains("sha1"))
                                m_resultTextEdit->appendPlainText(tr("  SHA-1: %1").arg(fileInfo["sha1"].toString()));
                            if (fileInfo.contains("md5"))
                                m_resultTextEdit->appendPlainText(tr("  MD5: %1").arg(fileInfo["md5"].toString()));
                            if (fileInfo.contains("size"))
                                m_resultTextEdit->appendPlainText(tr("  Size: %1 bytes").arg(fileInfo["size"].toInt()));
                        }
                        
                        // Add link to detailed results
                        if (data.contains("links") && data["links"].toObject().contains("self")) {
                            QString selfLink = data["links"].toObject()["self"].toString();
                            QString vtGuiLink = selfLink.replace("api/v3/", "gui/");
                            
                            m_resultTextEdit->appendPlainText(tr("\n🔍 To view detailed results:"));
                            m_resultTextEdit->appendPlainText(vtGuiLink);
                        }
                        
                        // Log completion
                        if (m_logTextEdit) {
                            m_logTextEdit->appendPlainText(QString("\n📊 %1 | VirusTotal analysis completed: %2 malicious, %3 suspicious, %4 clean")
                                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                                .arg(malicious)
                                .arg(suspicious)
                                .arg(undetected));
                        }
                        
                        // Update status bar
                        m_statusBar->showMessage(tr("VirusTotal analysis completed"));
                    }
                }
                // If no stats available but we have attributes, it might be a pending analysis
                else if (!attributes.contains("stats") || attributes["stats"].toObject().isEmpty()) {
                    // This is just the initial upload response, not the analysis result
                    m_resultTextEdit->appendPlainText(tr("\n✅ File successfully uploaded to VirusTotal."));
                    m_resultTextEdit->appendPlainText(tr("Analysis ID: %1").arg(analysisId));
                    m_resultTextEdit->appendPlainText(tr("\nResults are being analyzed, please wait..."));
                    
                    // Start auto-refresh timer
                    m_refreshTimer->start();
                    m_refreshAttempts = 0;
                    
                    // Update status bar
                    m_statusBar->showMessage(tr("VirusTotal analysis ongoing..."));
                    
                    // Log
                    if (m_logTextEdit) {
                        m_logTextEdit->appendPlainText(QString("\n✅ %1 | File uploaded to VirusTotal. Analysis ID: %2")
                            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                            .arg(analysisId));
                    }
                }
            } else {
                // This is just an initial file upload response without attributes
                fetchAnalysisResults(analysisId);
            }
        } 
        // Case 2: Direct file lookup result (when we request by hash)
        else if (type == "file") {
            // Stop any active refresh timer since we're getting direct file results
            if (m_refreshTimer->isActive()) {
                m_refreshTimer->stop();
                m_refreshAttempts = 0;
                m_currentAnalysisId.clear();
            }
            
            // Extract file information
            QJsonObject attributes = data["attributes"].toObject();
            
            // Display detailed results
            m_resultTextEdit->clear();
            m_resultTextEdit->appendPlainText(tr("VirusTotal File Report:"));
            m_resultTextEdit->appendPlainText(tr("--------------------------------------"));
            
            // File hashes
            m_resultTextEdit->appendPlainText(tr("\n📄 File Information:"));
            m_resultTextEdit->appendPlainText(tr("  SHA-256: %1").arg(attributes.contains("sha256") ? attributes["sha256"].toString() : data["id"].toString()));
            m_resultTextEdit->appendPlainText(tr("  SHA-1: %1").arg(attributes["sha1"].toString()));
            m_resultTextEdit->appendPlainText(tr("  MD5: %1").arg(attributes["md5"].toString()));
            m_resultTextEdit->appendPlainText(tr("  Size: %1 bytes").arg(attributes["size"].toInt()));
            
            // Format date if available
            if (attributes.contains("first_submission_date")) {
                QDateTime submissionDate = QDateTime::fromSecsSinceEpoch(attributes["first_submission_date"].toInt());
                m_resultTextEdit->appendPlainText(tr("  First Submission: %1").arg(
                    submissionDate.toString("yyyy-MM-dd hh:mm:ss")
                ));
            }
            
            // File type info
            if (attributes.contains("type_description")) {
                m_resultTextEdit->appendPlainText(tr("  File Type: %1").arg(attributes["type_description"].toString()));
            }
            
            // Stats info
            if (attributes.contains("last_analysis_stats")) {
                QJsonObject stats = attributes["last_analysis_stats"].toObject();
                
                int malicious = stats["malicious"].toInt();
                int suspicious = stats["suspicious"].toInt();
                int undetected = stats["undetected"].toInt();
                int total = malicious + suspicious + undetected;
                
                // Display scan statistics
                m_resultTextEdit->appendPlainText(tr("\n📊 Scan Summary:"));
                m_resultTextEdit->appendPlainText(tr("  🔴 Malicious: %1").arg(malicious));
                m_resultTextEdit->appendPlainText(tr("  🟠 Suspicious: %1").arg(suspicious));
                m_resultTextEdit->appendPlainText(tr("  🟢 Clean: %1").arg(undetected));
                m_resultTextEdit->appendPlainText(tr("  📈 Total: %1").arg(total));
                
                // Risk assessment
                QString risk;
                if (malicious > 0) {
                    risk = tr("🔴 HIGH RISK - %1 antivirus engines detected this file as malicious!").arg(malicious);
                } else if (suspicious > 0) {
                    risk = tr("🟠 MEDIUM RISK - %1 antivirus engines flagged this file as suspicious.").arg(suspicious);
                } else {
                    risk = tr("🟢 LOW RISK - No antivirus engines detected this file as malicious.");
                }
                
                m_resultTextEdit->appendPlainText(tr("\n⚠️ Risk Assessment:"));
                m_resultTextEdit->appendPlainText(risk);
                
                // Detailed AV results if available
                if (attributes.contains("last_analysis_results") && !attributes["last_analysis_results"].toObject().isEmpty()) {
                    QJsonObject avResults = attributes["last_analysis_results"].toObject();
                    m_resultTextEdit->appendPlainText(tr("\n🔍 Detailed Antivirus Scan Results:"));
                    
                    QStringList avNames = avResults.keys();
                    std::sort(avNames.begin(), avNames.end());  // Alfabetik sırala
                    
                    for (const QString &avName : avNames) {
                        QJsonObject avResult = avResults[avName].toObject();
                        QString category = avResult["category"].toString();
                        QString avVersion = avResult.contains("engine_version") ? avResult["engine_version"].toString() : "";
                        QString resultText = avResult.contains("result") ? avResult["result"].toString() : "";
                        
                        QString statusIcon;
                        if (category == "malicious") {
                            statusIcon = "🔴";
                        } else if (category == "suspicious") {
                            statusIcon = "🟠";
                        } else if (category == "undetected" || category == "harmless") {
                            statusIcon = "🟢";
                        } else {
                            statusIcon = "⚪";
                        }
                        
                        QString resultLine = QString("%1 %2").arg(statusIcon, avName);
                        if (!avVersion.isEmpty()) {
                            resultLine += QString(" (v%1)").arg(avVersion);
                        }
                        if (!resultText.isEmpty()) {
                            resultLine += QString(": %1").arg(resultText);
                        }
                        
                        m_resultTextEdit->appendPlainText(resultLine);
                    }
                }
                
                // Log
                if (m_logTextEdit) {
                    m_logTextEdit->appendPlainText(QString("\n📊 %1 | VirusTotal report obtained: %2 malicious, %3 suspicious, %4 clean")
                        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                        .arg(malicious)
                        .arg(suspicious)
                        .arg(undetected));
                }
            }
            
            // Add link to detailed results on VirusTotal website
            if (data.contains("links") && data["links"].toObject().contains("self")) {
                QString selfLink = data["links"].toObject()["self"].toString();
                QString vtGuiLink = selfLink.replace("api/v3/", "gui/");
                
                m_resultTextEdit->appendPlainText(tr("\n🔍 To view detailed results:"));
                m_resultTextEdit->appendPlainText(vtGuiLink);
            }
            
            // Update status bar
            m_statusBar->showMessage(tr("VirusTotal report obtained"));
        }
    }
}

void ScanManager::handleApiError(const QString& errorMessage)
{
    if (!m_resultTextEdit || !m_statusBar)
        return;
    
    // Check if this is a VirusTotal conflict error (duplicate file submission)
    if (errorMessage.contains("server replied:")) {
        // Log the full error for debugging
        if (m_logTextEdit) {
            m_logTextEdit->appendPlainText(QString("\n🔍 %1 | API error details: %2")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                .arg(errorMessage));
        }
        
        // Extract file hash from error message if available
        QString fileHash;
        QRegularExpression hashRegex("concurrent execution result for ([0-9a-f]+)");
        QRegularExpressionMatch match = hashRegex.match(errorMessage);
        
        if (match.hasMatch() && errorMessage.contains("ConflictError")) {
            fileHash = match.captured(1);
            
            // This is a duplicate submission - retrieve the existing analysis by file hash
            m_resultTextEdit->appendPlainText(tr("\n⚠️ This file has already been uploaded to VirusTotal."));
            m_resultTextEdit->appendPlainText(tr("🔄 Retrieving existing analysis results..."));
            
            if (!fileHash.isEmpty()) {
                // Log action
                if (m_logTextEdit) {
                    m_logTextEdit->appendPlainText(QString("\n🔄 %1 | File already analyzed, retrieving results by hash: %2")
                        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                        .arg(fileHash));
                }
                
                // Update status bar
                m_statusBar->showMessage(tr("Retrieving existing analysis results..."));
                
                // Request file report directly using the hash
                QString endpoint = QString("files/%1").arg(fileHash);
                m_apiManager->makeApiRequest(endpoint);
                return;
            }
        }
    }
    
    // Default error handling for other types of errors
    m_resultTextEdit->appendPlainText(tr("\n❌ API error: %1").arg(errorMessage));
    m_statusBar->showMessage(tr("API request failed"));
    
    // Log
    if (m_logTextEdit) {
        m_logTextEdit->appendPlainText(QString("\n❌ %1 | API error: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(errorMessage));
    }
}

void ScanManager::fetchAnalysisResults(const QString& analysisId)
{
    // Update UI with initial status
    m_resultTextEdit->appendPlainText(tr("\nVirusTotal Analysis Results:"));
    m_resultTextEdit->appendPlainText(tr("--------------------------------------"));
    m_resultTextEdit->appendPlainText(tr("✅ File successfully uploaded to VirusTotal."));
    m_resultTextEdit->appendPlainText(tr("📋 Analysis ID: %1").arg(analysisId));
    m_resultTextEdit->appendPlainText(tr("\n🔄 Retrieving analysis results... Please wait..."));
    
    // Log the action
    if (m_logTextEdit) {
        m_logTextEdit->appendPlainText(QString("\n🔄 %1 | Retrieving analysis results: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(analysisId));
    }
    
    // Update status bar
    if (m_statusBar) {
        m_statusBar->showMessage(tr("Retrieving VirusTotal analysis results..."));
    }
    
    // Make API request to get analysis results
    QString endpoint = QString("analyses/%1").arg(analysisId);
    m_apiManager->makeApiRequest(endpoint);
    
    // Note: The results will be handled in handleApiResponse method when the response arrives
}

void ScanManager::checkAnalysisStatus()
{
    // Eğer bir analiz ID'si yoksa timer'ı durdur
    if (m_currentAnalysisId.isEmpty()) {
        m_refreshTimer->stop();
        m_refreshAttempts = 0;
        return;
    }
    
    // Maksimum deneme sayısını kontrol et (10 deneme = ~100 saniye)
    if (m_refreshAttempts >= MAX_REFRESH_ATTEMPTS) {
        m_refreshTimer->stop();
        m_refreshAttempts = 0;
        
        // Log ve kullanıcıya bildir
        if (m_logTextEdit) {
            m_logTextEdit->appendPlainText(QString("\n⚠️ %1 | Maximum wait time exceeded for analysis results: %2")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                .arg(m_currentAnalysisId));
        }
        
        if (m_resultTextEdit) {
            m_resultTextEdit->appendPlainText(tr("\n⚠️ Maximum wait time exceeded for analysis results."));
            m_resultTextEdit->appendPlainText(tr("Analysis may still be ongoing. Please try again later or use the link below:"));
            m_resultTextEdit->appendPlainText(tr("https://www.virustotal.com/gui/analyses/%1").arg(m_currentAnalysisId));
        }
        
        return;
    }
    
    // Deneme sayısını artır
    m_refreshAttempts++;
    
    if (m_logTextEdit) {
        m_logTextEdit->appendPlainText(QString("\n🔄 %1 | Checking analysis results (Attempt %2/%3): %4")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(m_refreshAttempts)
            .arg(MAX_REFRESH_ATTEMPTS)
            .arg(m_currentAnalysisId));
    }
    
    // API isteği yap
    QString endpoint = QString("analyses/%1").arg(m_currentAnalysisId);
    m_apiManager->makeApiRequest(endpoint);
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
    if (!m_yaraManager)
        return false;
    
    try {
        // YaraRuleManager doesn't have isInitialized() method
        // Instead we'll check if rules are loaded, which indicates initialization was successful
        // or we can attempt calling initialize() which should return no error if already initialized
        std::error_code error = m_yaraManager->initialize();
        return !error; // If error code is 0 (no error), then it's initialized
    }
    catch (...) {
        // Herhangi bir hata durumunda false döndür
        return false;
    }
}