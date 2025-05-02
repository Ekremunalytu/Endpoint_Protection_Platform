#include "../Headers/ScanManager.h"
#include "../Headers/ApiManager.h"
#include "../Headers/YaraRuleManager.h"
#include "../Headers/CdrManager.h"
#include "../Headers/SandboxManager.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>

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
        qDebug() << "YARA başlatma hatası:" << QString::fromStdString(error.message());
    } else {
        qDebug() << "YARA başarıyla başlatıldı.";
        
        // Kuralları yükle
        QString rulePath = QCoreApplication::applicationDirPath() + "/Rules/test.yar";
        error = m_yaraManager->loadRules(rulePath.toStdString());
        if (error) {
            qDebug() << "YARA kuralları yüklenirken hata oluştu:" << QString::fromStdString(error.message());
        } else {
            qDebug() << "YARA kuralları başarıyla yüklendi.";
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
    if (!m_resultTextEdit || !m_statusBar || !m_logTextEdit)
        return;
    
    // Durum mesajını güncelle
    m_statusBar->showMessage(tr("Dosya taranıyor: %1").arg(filePath));
    
    // Log'a ekle
    m_logTextEdit->appendPlainText(QString("\n🔍 %1 | Dosya taranıyor: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(filePath));
    
    // Sonuç alanını temizle ve ilk bilgiyi göster
    m_resultTextEdit->clear();
    m_resultTextEdit->appendPlainText(tr("Dosya taranıyor: %1\n").arg(filePath));
    m_resultTextEdit->appendPlainText(tr("Offline tarama için YARA kuralları kullanılıyor...\n"));
    
    // YARA motoru ile offline tarama yap
    std::vector<std::string> matchesVector;
    std::error_code error = m_yaraManager->scanFile(filePath.toStdString(), matchesVector);
    
    // Convert std::vector<std::string> to QStringList
    QStringList matches;
    for (const auto& match : matchesVector) {
        matches.append(QString::fromStdString(match));
    }
    
    if (error) {
        m_resultTextEdit->appendPlainText(tr("❌ Tarama sırasında hata oluştu: %1").arg(QString::fromStdString(error.message())));
    } else if (matches.isEmpty()) {
        m_resultTextEdit->appendPlainText(tr("✅ Dosyada hiçbir tehdit tespit edilmedi."));
    } else {
        m_resultTextEdit->appendPlainText(tr("⚠️ Dosyada potansiyel tehditler tespit edildi!\n"));
        m_resultTextEdit->appendPlainText(tr("Eşleşen YARA kuralları:"));
        
        for (const QString &match : matches) {
            m_resultTextEdit->appendPlainText(tr("- %1").arg(match));
        }
        
        m_resultTextEdit->appendPlainText(tr("\n⚠️ Bu dosya zararlı olabilir. Dikkatli olun!"));
    }
    
    // İsteğe bağlı olarak, daha fazla analiz için VirusTotal'e yönlendirebiliriz
    if (!matches.isEmpty()) {
        m_resultTextEdit->appendPlainText(tr("\nDaha detaylı analiz için 'VirusTotal Tarama' özelliğini kullanabilirsiniz."));
    }
    
    // Durum çubuğunu güncelle
    m_statusBar->showMessage(tr("Tarama tamamlandı"));
}

void ScanManager::performOnlineScan(const QString& filePath)
{
    if (!m_resultTextEdit || !m_statusBar || !m_logTextEdit)
        return;
    
    // API Key kontrolü
    if (m_apiManager->getApiKey().isEmpty()) {
        m_logTextEdit->appendPlainText(QString("\n⚠️ %1 | API anahtarı bulunamadı")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
        QMessageBox::warning(nullptr, tr("API Key Gerekli"), 
                           tr("VirusTotal taraması için API anahtarı gerekli.\n"
                              "Lütfen önce 'API Key Ayarla' seçeneğini kullanın."));
        return;
    }
    
    // Durum mesajını güncelle
    m_statusBar->showMessage(tr("Dosya VirusTotal'e gönderiliyor: %1").arg(filePath));
    
    // API isteğinden önce temizle ve bilgi mesajı göster
    m_resultTextEdit->clear();
    m_resultTextEdit->appendPlainText(tr("Dosya VirusTotal'e gönderiliyor: %1").arg(filePath));
    m_resultTextEdit->appendPlainText(tr("Bu işlem dosya boyutuna bağlı olarak biraz zaman alabilir..."));
    
    // Dosya içeriğini okumalı ve multipart form olarak göndermeli
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        m_resultTextEdit->appendPlainText(tr("\n❌ Dosya açılamadı: %1").arg(filePath));
        m_logTextEdit->appendPlainText(QString("\n❌ %1 | Dosya açılamadı: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(filePath));
        return;
    }
    
    // Dosya verilerini oku
    QByteArray fileData = file.readAll();
    file.close();
    
    if (fileData.isEmpty()) {
        m_resultTextEdit->appendPlainText(tr("\n❌ Dosya boş: %1").arg(filePath));
        return;
    }
    
    // Dosya adını al (yalnızca dosya adı, yolu olmadan)
    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();
    
    // VirusTotal'e dosyayı gönder
    m_apiManager->uploadFileToVirusTotal(filePath, fileName, fileData);
    
    m_logTextEdit->appendPlainText(QString("\n📤 %1 | VirusTotal'e dosya gönderiliyor: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(filePath));
}

void ScanManager::performCdrScan(const QString& filePath)
{
    if (!m_resultTextEdit || !m_statusBar || !m_logTextEdit || !m_cdrManager)
        return;
    
    // Docker kontrolü
    if (!m_cdrManager->initialize()) {
        m_logTextEdit->appendPlainText(QString("\n⚠️ %1 | Docker kullanılamıyor - CDR işlemi yapılamadı")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
        QMessageBox::warning(nullptr, tr("Docker Gerekli"), 
                           tr("CDR işlemi için Docker gerekli. Lütfen Docker'ın çalıştığından emin olun."));
        return;
    }
    
    // Durum mesajını güncelle
    m_statusBar->showMessage(tr("CDR işlemi başlatılıyor: %1").arg(filePath));
    
    // Temizle ve bilgi mesajı göster
    m_resultTextEdit->clear();
    m_resultTextEdit->appendPlainText(tr("Dosya içeriği temizleniyor: %1").arg(filePath));
    m_resultTextEdit->appendPlainText(tr("CDR (Content Disarm and Reconstruction) işlemi başlatıldı..."));
    m_resultTextEdit->appendPlainText(tr("Dosya analiz ediliyor ve zararlı içerikler temizleniyor."));
    
    // CDR işlemini başlat
    bool success = m_cdrManager->processFile(filePath);
    QString outputPath = success ? m_cdrManager->getCleanedFilePath(filePath) : "";
    
    if (outputPath.isEmpty()) {
        m_resultTextEdit->appendPlainText(tr("\n❌ CDR işlemi başarısız oldu."));
        m_logTextEdit->appendPlainText(QString("\n❌ %1 | CDR işlemi başarısız: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(filePath));
    } else {
        m_resultTextEdit->appendPlainText(tr("\n✅ CDR işlemi başarıyla tamamlandı."));
        m_resultTextEdit->appendPlainText(tr("Temizlenmiş dosya kaydedildi: %1").arg(outputPath));
        m_logTextEdit->appendPlainText(QString("\n✅ %1 | CDR işlemi başarılı: %2 -> %3")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(filePath)
            .arg(outputPath));
    }
    
    // Durum çubuğunu güncelle
    m_statusBar->showMessage(tr("CDR işlemi tamamlandı"));
}

void ScanManager::performSandboxScan(const QString& filePath)
{
    if (!m_resultTextEdit || !m_statusBar || !m_logTextEdit || !m_sandboxManager)
        return;
    
    // Docker kontrolü
    if (!m_sandboxManager->initialize()) {
        m_logTextEdit->appendPlainText(QString("\n⚠️ %1 | Docker kullanılamıyor - Sandbox analizi yapılamadı")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
        QMessageBox::warning(nullptr, tr("Docker Gerekli"), 
                           tr("Sandbox analizi için Docker gerekli. Lütfen Docker'ın çalıştığından emin olun."));
        return;
    }
    
    // Durum mesajını güncelle
    m_statusBar->showMessage(tr("Sandbox analizi başlatılıyor: %1").arg(filePath));
    
    // Temizle ve bilgi mesajı göster
    m_resultTextEdit->clear();
    m_resultTextEdit->appendPlainText(tr("Dosya güvenli bir ortamda analiz ediliyor: %1").arg(filePath));
    m_resultTextEdit->appendPlainText(tr("Sandbox analizi başlatıldı..."));
    m_resultTextEdit->appendPlainText(tr("Bu işlem dosya türüne bağlı olarak birkaç dakika sürebilir."));
    
    // Sandbox analizi başlat
    bool success = m_sandboxManager->analyzeFile(filePath);
    
    if (success) {
        QJsonObject results = m_sandboxManager->getAnalysisResults();
        QString analysisResult = QJsonDocument(results).toJson(QJsonDocument::Indented);
        m_resultTextEdit->appendPlainText(tr("\n✅ Sandbox analizi tamamlandı."));
        m_resultTextEdit->appendPlainText(tr("\nANALİZ SONUÇLARI:"));
        m_resultTextEdit->appendPlainText(analysisResult);
        
        m_logTextEdit->appendPlainText(QString("\n✅ %1 | Sandbox analizi tamamlandı: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(filePath));
    } else {
        m_resultTextEdit->appendPlainText(tr("\n❌ Sandbox analizi başarısız oldu."));
        m_logTextEdit->appendPlainText(QString("\n❌ %1 | Sandbox analizi başarısız: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(filePath));
    }
    
    // Durum çubuğunu güncelle
    m_statusBar->showMessage(tr("Sandbox analizi tamamlandı"));
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
                            m_logTextEdit->appendPlainText(QString("\n⏳ %1 | Analiz %2 durumunda, otomatik yenileme başlatıldı: %3")
                                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                                .arg(status)
                                .arg(analysisId));
                        }
                    }
                    
                    // Update UI to show waiting status if results are empty
                    if (attributes.contains("results") && attributes["results"].toObject().isEmpty()) {
                        if (!status.isEmpty()) {
                            m_resultTextEdit->appendPlainText(tr("\n⏳ Analiz durumu: %1").arg(status));
                            m_resultTextEdit->appendPlainText(tr("Sonuçlar henüz hazır değil. Otomatik olarak yenilenecek..."));
                            m_statusBar->showMessage(tr("VirusTotal analizi devam ediyor (%1)...").arg(status));
                        }
                    }
                } 
                else if (status == "completed") {
                    // Analysis is complete, stop auto-refresh timer
                    if (m_refreshTimer->isActive()) {
                        m_refreshTimer->stop();
                        m_refreshAttempts = 0;
                        
                        if (m_logTextEdit) {
                            m_logTextEdit->appendPlainText(QString("\n✅ %1 | Analiz tamamlandı, otomatik yenileme durduruldu: %2")
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
                        m_resultTextEdit->appendPlainText(tr("VirusTotal Analiz Sonuçları:"));
                        m_resultTextEdit->appendPlainText(tr("--------------------------------------"));
                        m_resultTextEdit->appendPlainText(tr("📋 Analiz Kimliği: %1").arg(analysisId));
                        
                        // Format date if available
                        if (attributes.contains("date")) {
                            QDateTime analysisDate = QDateTime::fromSecsSinceEpoch(attributes["date"].toInt());
                            m_resultTextEdit->appendPlainText(tr("📅 Analiz Tarihi: %1").arg(
                                analysisDate.toString("yyyy-MM-dd hh:mm:ss")
                            ));
                        }
                        
                        // Display scan statistics
                        m_resultTextEdit->appendPlainText(tr("\n📊 Tarama Özeti:"));
                        m_resultTextEdit->appendPlainText(tr("  🔴 Zararlı: %1").arg(malicious));
                        m_resultTextEdit->appendPlainText(tr("  🟠 Şüpheli: %1").arg(suspicious));
                        m_resultTextEdit->appendPlainText(tr("  🟢 Temiz: %1").arg(undetected));
                        m_resultTextEdit->appendPlainText(tr("  ⚪ Zaman Aşımı: %1").arg(timeout));
                        m_resultTextEdit->appendPlainText(tr("  📈 Toplam: %1").arg(total));
                        
                        // Risk assessment
                        QString risk;
                        if (malicious > 0) {
                            risk = tr("🔴 YÜKSEK RİSK - %1 antivirüs motoru bu dosyayı zararlı olarak tespit etti!").arg(malicious);
                        } else if (suspicious > 0) {
                            risk = tr("🟠 ORTA RİSK - %1 antivirüs motoru bu dosyayı şüpheli olarak işaretledi.").arg(suspicious);
                        } else {
                            risk = tr("🟢 DÜŞÜK RİSK - Hiçbir antivirüs bu dosyayı zararlı olarak tespit etmedi.");
                        }
                        
                        m_resultTextEdit->appendPlainText(tr("\n⚠️ Risk Değerlendirmesi:"));
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
                            m_resultTextEdit->appendPlainText(tr("\n📄 Dosya Bilgileri:"));
                            if (fileInfo.contains("sha256"))
                                m_resultTextEdit->appendPlainText(tr("  SHA-256: %1").arg(fileInfo["sha256"].toString()));
                            if (fileInfo.contains("sha1"))
                                m_resultTextEdit->appendPlainText(tr("  SHA-1: %1").arg(fileInfo["sha1"].toString()));
                            if (fileInfo.contains("md5"))
                                m_resultTextEdit->appendPlainText(tr("  MD5: %1").arg(fileInfo["md5"].toString()));
                            if (fileInfo.contains("size"))
                                m_resultTextEdit->appendPlainText(tr("  Boyut: %1 bayt").arg(fileInfo["size"].toInt()));
                        }
                        
                        // Add link to detailed results
                        if (data.contains("links") && data["links"].toObject().contains("self")) {
                            QString selfLink = data["links"].toObject()["self"].toString();
                            QString vtGuiLink = selfLink.replace("api/v3/", "gui/");
                            
                            m_resultTextEdit->appendPlainText(tr("\n🔍 Detaylı sonuçları görmek için:"));
                            m_resultTextEdit->appendPlainText(vtGuiLink);
                        }
                        
                        // Log completion
                        if (m_logTextEdit) {
                            m_logTextEdit->appendPlainText(QString("\n📊 %1 | VirusTotal analizi tamamlandı: %2 zararlı, %3 şüpheli, %4 temiz")
                                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                                .arg(malicious)
                                .arg(suspicious)
                                .arg(undetected));
                        }
                        
                        // Update status bar
                        m_statusBar->showMessage(tr("VirusTotal analizi tamamlandı"));
                    }
                }
                // If no stats available but we have attributes, it might be a pending analysis
                else if (!attributes.contains("stats") || attributes["stats"].toObject().isEmpty()) {
                    // This is just the initial upload response, not the analysis result
                    m_resultTextEdit->appendPlainText(tr("\n✅ Dosya başarıyla VirusTotal'e yüklendi."));
                    m_resultTextEdit->appendPlainText(tr("Analiz kimliği: %1").arg(analysisId));
                    m_resultTextEdit->appendPlainText(tr("\nSonuçlar analiz edilirken lütfen bekleyin..."));
                    
                    // Start auto-refresh timer
                    m_refreshTimer->start();
                    m_refreshAttempts = 0;
                    
                    // Update status bar
                    m_statusBar->showMessage(tr("VirusTotal analizi devam ediyor..."));
                    
                    // Log
                    if (m_logTextEdit) {
                        m_logTextEdit->appendPlainText(QString("\n✅ %1 | Dosya VirusTotal'e yüklendi. Analiz ID: %2")
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
            m_resultTextEdit->appendPlainText(tr("VirusTotal Dosya Raporu:"));
            m_resultTextEdit->appendPlainText(tr("--------------------------------------"));
            
            // File hashes
            m_resultTextEdit->appendPlainText(tr("\n📄 Dosya Bilgileri:"));
            m_resultTextEdit->appendPlainText(tr("  SHA-256: %1").arg(attributes.contains("sha256") ? attributes["sha256"].toString() : data["id"].toString()));
            m_resultTextEdit->appendPlainText(tr("  SHA-1: %1").arg(attributes["sha1"].toString()));
            m_resultTextEdit->appendPlainText(tr("  MD5: %1").arg(attributes["md5"].toString()));
            m_resultTextEdit->appendPlainText(tr("  Boyut: %1 bayt").arg(attributes["size"].toInt()));
            
            // Format date if available
            if (attributes.contains("first_submission_date")) {
                QDateTime submissionDate = QDateTime::fromSecsSinceEpoch(attributes["first_submission_date"].toInt());
                m_resultTextEdit->appendPlainText(tr("  İlk Gönderim: %1").arg(
                    submissionDate.toString("yyyy-MM-dd hh:mm:ss")
                ));
            }
            
            // File type info
            if (attributes.contains("type_description")) {
                m_resultTextEdit->appendPlainText(tr("  Dosya Türü: %1").arg(attributes["type_description"].toString()));
            }
            
            // Stats info
            if (attributes.contains("last_analysis_stats")) {
                QJsonObject stats = attributes["last_analysis_stats"].toObject();
                
                int malicious = stats["malicious"].toInt();
                int suspicious = stats["suspicious"].toInt();
                int undetected = stats["undetected"].toInt();
                int total = malicious + suspicious + undetected;
                
                // Display scan statistics
                m_resultTextEdit->appendPlainText(tr("\n📊 Tarama Özeti:"));
                m_resultTextEdit->appendPlainText(tr("  🔴 Zararlı: %1").arg(malicious));
                m_resultTextEdit->appendPlainText(tr("  🟠 Şüpheli: %1").arg(suspicious));
                m_resultTextEdit->appendPlainText(tr("  🟢 Temiz: %1").arg(undetected));
                m_resultTextEdit->appendPlainText(tr("  📈 Toplam: %1").arg(total));
                
                // Risk assessment
                QString risk;
                if (malicious > 0) {
                    risk = tr("🔴 YÜKSEK RİSK - %1 antivirüs motoru bu dosyayı zararlı olarak tespit etti!").arg(malicious);
                } else if (suspicious > 0) {
                    risk = tr("🟠 ORTA RİSK - %1 antivirüs motoru bu dosyayı şüpheli olarak işaretledi.").arg(suspicious);
                } else {
                    risk = tr("🟢 DÜŞÜK RİSK - Hiçbir antivirüs bu dosyayı zararlı olarak tespit etmedi.");
                }
                
                m_resultTextEdit->appendPlainText(tr("\n⚠️ Risk Değerlendirmesi:"));
                m_resultTextEdit->appendPlainText(risk);
                
                // Detailed AV results if available
                if (attributes.contains("last_analysis_results") && !attributes["last_analysis_results"].toObject().isEmpty()) {
                    QJsonObject avResults = attributes["last_analysis_results"].toObject();
                    m_resultTextEdit->appendPlainText(tr("\n🔍 Detaylı Antivirüs Tarama Sonuçları:"));
                    
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
                    m_logTextEdit->appendPlainText(QString("\n📊 %1 | VirusTotal raporu alındı: %2 zararlı, %3 şüpheli, %4 temiz")
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
                
                m_resultTextEdit->appendPlainText(tr("\n🔍 Detaylı sonuçları görmek için:"));
                m_resultTextEdit->appendPlainText(vtGuiLink);
            }
            
            // Update status bar
            m_statusBar->showMessage(tr("VirusTotal raporu alındı"));
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
            m_logTextEdit->appendPlainText(QString("\n🔍 %1 | API hata detayı: %2")
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
            m_resultTextEdit->appendPlainText(tr("\n⚠️ Bu dosya daha önce VirusTotal'e yüklenmiş."));
            m_resultTextEdit->appendPlainText(tr("🔄 Mevcut analiz sonucu alınıyor..."));
            
            if (!fileHash.isEmpty()) {
                // Log action
                if (m_logTextEdit) {
                    m_logTextEdit->appendPlainText(QString("\n🔄 %1 | Dosya zaten analiz edilmiş, hash ile sonuçlar alınıyor: %2")
                        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                        .arg(fileHash));
                }
                
                // Update status bar
                m_statusBar->showMessage(tr("Mevcut analiz sonucu alınıyor..."));
                
                // Request file report directly using the hash
                QString endpoint = QString("files/%1").arg(fileHash);
                m_apiManager->makeApiRequest(endpoint);
                return;
            }
        }
    }
    
    // Default error handling for other types of errors
    m_resultTextEdit->appendPlainText(tr("\n❌ API hatası: %1").arg(errorMessage));
    m_statusBar->showMessage(tr("API isteği başarısız"));
    
    // Log
    if (m_logTextEdit) {
        m_logTextEdit->appendPlainText(QString("\n❌ %1 | API hatası: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(errorMessage));
    }
}

void ScanManager::fetchAnalysisResults(const QString& analysisId)
{
    // Update UI with initial status
    m_resultTextEdit->appendPlainText(tr("\nVirusTotal Analiz Sonuçları:"));
    m_resultTextEdit->appendPlainText(tr("--------------------------------------"));
    m_resultTextEdit->appendPlainText(tr("✅ Dosya başarıyla VirusTotal'e yüklendi."));
    m_resultTextEdit->appendPlainText(tr("📋 Analiz Kimliği: %1").arg(analysisId));
    m_resultTextEdit->appendPlainText(tr("\n🔄 Analiz sonuçları alınıyor... Lütfen bekleyin..."));
    
    // Log the action
    if (m_logTextEdit) {
        m_logTextEdit->appendPlainText(QString("\n🔄 %1 | Analiz sonuçları alınıyor: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(analysisId));
    }
    
    // Update status bar
    if (m_statusBar) {
        m_statusBar->showMessage(tr("VirusTotal analiz sonuçları alınıyor..."));
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
            m_logTextEdit->appendPlainText(QString("\n⚠️ %1 | Analiz sonuçları için maksimum bekleme süresi aşıldı: %2")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                .arg(m_currentAnalysisId));
        }
        
        if (m_resultTextEdit) {
            m_resultTextEdit->appendPlainText(tr("\n⚠️ Analiz sonuçları için maksimum bekleme süresi aşıldı."));
            m_resultTextEdit->appendPlainText(tr("Analiz hala devam ediyor olabilir. Lütfen daha sonra tekrar deneyin veya aşağıdaki bağlantıyı kullanın:"));
            m_resultTextEdit->appendPlainText(tr("https://www.virustotal.com/gui/analyses/%1").arg(m_currentAnalysisId));
        }
        
        return;
    }
    
    // Deneme sayısını artır
    m_refreshAttempts++;
    
    if (m_logTextEdit) {
        m_logTextEdit->appendPlainText(QString("\n🔄 %1 | Analiz sonuçları kontrol ediliyor (Deneme %2/%3): %4")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(m_refreshAttempts)
            .arg(MAX_REFRESH_ATTEMPTS)
            .arg(m_currentAnalysisId));
    }
    
    // API isteği yap
    QString endpoint = QString("analyses/%1").arg(m_currentAnalysisId);
    m_apiManager->makeApiRequest(endpoint);
}