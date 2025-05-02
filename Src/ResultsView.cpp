#include "../Headers/ResultsView.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QDateTime>
#include <algorithm>

ResultsView::ResultsView(QObject *parent)
    : QObject(parent),
      m_resultTextEdit(nullptr),
      m_detailedResultTextEdit(nullptr)
{
}

ResultsView::~ResultsView()
{
    // UI bileşenlerini silmeye gerek yok, bunlar ana pencere tarafından yönetilir
}

void ResultsView::setResultTextEdit(QPlainTextEdit* resultTextEdit)
{
    m_resultTextEdit = resultTextEdit;
}

void ResultsView::setDetailedResultTextEdit(QPlainTextEdit* detailedTextEdit)
{
    m_detailedResultTextEdit = detailedTextEdit;
}

void ResultsView::setupTextEditStyle(QPlainTextEdit* textEdit)
{
    if (!textEdit) return;
    
    // Metin düzenleyici stil ayarları
    textEdit->setStyleSheet(
        "QPlainTextEdit {"
        "    background-color: #181818;"
        "    color: #cccccc;"
        "    border: none;"
        "    font-family: 'Consolas', 'Courier New', monospace;"
        "    font-size: 12pt;"
        "    padding: 10px;"
        "}"
        "QScrollBar:vertical {"
        "    background: #222222;"
        "    width: 12px;"
        "    margin: 0px;"
        "}"
        "QScrollBar::handle:vertical {"
        "    background: #444444;"
        "    min-height: 20px;"
        "    border-radius: 6px;"
        "}"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
        "    height: 0px;"
        "}"
    );
    
    // Satır sayısı için sol kenar boşluğu
    textEdit->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    textEdit->document()->setDocumentMargin(15);
}

void ResultsView::showNormalResults(const QJsonObject& response)
{
    if (!m_resultTextEdit) return;
    
    // Null kontrol
    if (response.isEmpty()) {
        m_resultTextEdit->appendPlainText("❌ API yanıtı boş veya geçersiz.");
        return;
    }

    // Data nesnesini kontrol et
    if (!response.contains("data") || response["data"].isNull()) {
        m_resultTextEdit->appendPlainText("❌ Üzgünüz, dosya tarama sonuçları alınamadı.");
        return;
    }

    QJsonObject data = response["data"].toObject();
    
    // Attributes nesnesini kontrol et
    if (!data.contains("attributes") || data["attributes"].isNull()) {
        m_resultTextEdit->appendPlainText("❌ Dosya analiz sonuçları bulunamadı.");
        return;
    }

    QJsonObject attributes = data["attributes"].toObject();
    
    // Başlık
    m_resultTextEdit->appendPlainText("=== Dosya Güvenlik Raporu ===\n");
    
    // Genel Değerlendirme - Güvenli kontrol
    if (attributes.contains("stats") && !attributes["stats"].isNull()) {
        QJsonObject stats = attributes["stats"].toObject();
        int malicious = stats.contains("malicious") ? stats["malicious"].toInt() : 0;
        int suspicious = stats.contains("suspicious") ? stats["suspicious"].toInt() : 0;
        
        // Güvenlik durumu
        if (malicious > 0) {
            m_resultTextEdit->appendPlainText("⛔ TEHLİKE DURUMU");
            m_resultTextEdit->appendPlainText("------------------");
            m_resultTextEdit->appendPlainText("Bu dosya zararlı yazılım içerebilir!");
            m_resultTextEdit->appendPlainText(QString("🔴 %1 antivirüs programı bu dosyayı zararlı olarak tespit etti.").arg(malicious));
        } else if (suspicious > 0) {
            m_resultTextEdit->appendPlainText("⚠️ DİKKAT");
            m_resultTextEdit->appendPlainText("------------------");
            m_resultTextEdit->appendPlainText("Bu dosya şüpheli davranışlar gösteriyor.");
            m_resultTextEdit->appendPlainText(QString("🟡 %1 antivirüs programı bu dosyayı şüpheli buluyor.").arg(suspicious));
        } else {
            m_resultTextEdit->appendPlainText("✅ GÜVENLİ");
            m_resultTextEdit->appendPlainText("------------------");
            m_resultTextEdit->appendPlainText("Bu dosyada herhangi bir tehdit tespit edilmedi.");
        }
        m_resultTextEdit->appendPlainText("");
    }

    // Dosya Bilgileri
    m_resultTextEdit->appendPlainText("\n📄 DOSYA BİLGİLERİ");
    m_resultTextEdit->appendPlainText("------------------");
    if (attributes.contains("meaningful_name") && !attributes["meaningful_name"].isNull()) {
        m_resultTextEdit->appendPlainText(QString("📝 Dosya Adı: %1").arg(attributes["meaningful_name"].toString()));
    }
    if (attributes.contains("type_description") && !attributes["type_description"].isNull()) {
        m_resultTextEdit->appendPlainText(QString("📁 Dosya Türü: %1").arg(attributes["type_description"].toString()));
    }
    if (attributes.contains("size") && !attributes["size"].isNull()) {
        double sizeInMB = attributes["size"].toDouble() / (1024 * 1024);
        m_resultTextEdit->appendPlainText(QString("💾 Boyut: %1 MB").arg(sizeInMB, 0, 'f', 2));
    }

    // Topluluk Değerlendirmesi
    if (attributes.contains("total_votes") && !attributes["total_votes"].isNull()) {
        QJsonObject votes = attributes["total_votes"].toObject();
        int harmlessVotes = votes.contains("harmless") ? votes["harmless"].toInt() : 0;
        int maliciousVotes = votes.contains("malicious") ? votes["malicious"].toInt() : 0;
        
        if (harmlessVotes > 0 || maliciousVotes > 0) {
            m_resultTextEdit->appendPlainText("\n👥 TOPLULUK YORUMLARI");
            m_resultTextEdit->appendPlainText("------------------");
            m_resultTextEdit->appendPlainText(QString("👍 %1 kullanıcı bu dosyanın güvenli olduğunu düşünüyor").arg(harmlessVotes));
            m_resultTextEdit->appendPlainText(QString("👎 %1 kullanıcı bu dosyanın zararlı olduğunu düşünüyor").arg(maliciousVotes));
        }
    }

    // Öneriler
    m_resultTextEdit->appendPlainText("\n💡 ÖNERİLER");
    m_resultTextEdit->appendPlainText("------------------");
    if (attributes.contains("stats") && !attributes["stats"].isNull()) {
        QJsonObject stats = attributes["stats"].toObject();
        int malicious = stats.contains("malicious") ? stats["malicious"].toInt() : 0;
        int suspicious = stats.contains("suspicious") ? stats["suspicious"].toInt() : 0;
        
        if (malicious > 0) {
            m_resultTextEdit->appendPlainText("❗ Bu dosyayı çalıştırmanız önerilmez!");
            m_resultTextEdit->appendPlainText("❗ Dosyayı hemen silin veya karantinaya alın.");
            m_resultTextEdit->appendPlainText("❗ Sisteminizi tam taramadan geçirin.");
        } else if (suspicious > 0) {
            m_resultTextEdit->appendPlainText("⚠️ Bu dosyayı güvenilir bir kaynaktan aldıysanız kullanabilirsiniz.");
            m_resultTextEdit->appendPlainText("⚠️ Emin değilseniz, dosyayı çalıştırmadan önce bir güvenlik uzmanına danışın.");
        } else {
            m_resultTextEdit->appendPlainText("✅ Bu dosyayı güvenle kullanabilirsiniz.");
            m_resultTextEdit->appendPlainText("💡 Yine de her zaman güncel bir antivirüs kullanmanızı öneririz.");
        }
    }
}

void ResultsView::showDetailedResults(const QJsonObject& response)
{
    if (!m_detailedResultTextEdit) return;
    m_detailedResultTextEdit->clear();
    
    // Null kontrol
    if (response.isEmpty()) {
        m_detailedResultTextEdit->appendPlainText("❌ API yanıtı boş veya geçersiz.");
        return;
    }

    // Data nesnesini kontrol et
    if (!response.contains("data") || response["data"].isNull()) {
        m_detailedResultTextEdit->appendPlainText("❌ Üzgünüz, detaylı dosya tarama sonuçları alınamadı.");
        return;
    }

    QJsonObject data = response["data"].toObject();
    QString dataType = data.contains("type") ? data["type"].toString() : "";
    
    // Başlık ve genel bilgiler
    m_detailedResultTextEdit->appendPlainText("=============== DETAYLI ANALİZ RAPORU ================\n");
    
    // Attributes nesnesini kontrol et
    if (!data.contains("attributes") || data["attributes"].isNull()) {
        m_detailedResultTextEdit->appendPlainText("❌ Detaylı dosya analiz sonuçları bulunamadı.");
        return;
    }

    QJsonObject attributes = data["attributes"].toObject();
    
    // İlk analiz ID'sini ekle
    QString analysisId = data["id"].toString();
    if (!analysisId.isEmpty()) {
        m_detailedResultTextEdit->appendPlainText(QString("🔍 Analiz ID: %1").arg(analysisId));
        m_detailedResultTextEdit->appendPlainText("==================================\n");
    }
    
    // META - Dosya Bilgileri
    // File info from meta section (available in both analysis and file responses)
    QJsonObject fileInfo;
    if (response.contains("meta") && response["meta"].toObject().contains("file_info")) {
        fileInfo = response["meta"].toObject()["file_info"].toObject();
    } else if (attributes.contains("meta") && attributes["meta"].toObject().contains("file_info")) {
        fileInfo = attributes["meta"].toObject()["file_info"].toObject();
    }
    
    if (!fileInfo.isEmpty()) {
        m_detailedResultTextEdit->appendPlainText("📄 DOSYA BİLGİLERİ");
        m_detailedResultTextEdit->appendPlainText("==================================");
        
        if (fileInfo.contains("sha256"))
            m_detailedResultTextEdit->appendPlainText(QString("🔒 SHA-256: %1").arg(fileInfo["sha256"].toString()));
        if (fileInfo.contains("sha1"))
            m_detailedResultTextEdit->appendPlainText(QString("🔒 SHA-1: %1").arg(fileInfo["sha1"].toString()));
        if (fileInfo.contains("md5"))
            m_detailedResultTextEdit->appendPlainText(QString("🔒 MD5: %1").arg(fileInfo["md5"].toString()));
        if (fileInfo.contains("size"))
            m_detailedResultTextEdit->appendPlainText(QString("💾 Boyut: %1 byte").arg(fileInfo["size"].toInt()));
        
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // Tarama Durumu
    if (attributes.contains("status")) {
        QString status = attributes["status"].toString();
        m_detailedResultTextEdit->appendPlainText("🔄 TARAMA DURUMU");
        m_detailedResultTextEdit->appendPlainText("==================================");
        
        if (status == "completed") {
            m_detailedResultTextEdit->appendPlainText("✅ Tarama tamamlandı");
        } else if (status == "queued") {
            m_detailedResultTextEdit->appendPlainText("⏳ Tarama sıraya alındı - sonuçlar henüz hazır değil");
            m_detailedResultTextEdit->appendPlainText("Sistem tarama sırasını bekliyor...");
        } else if (status == "in-progress") {
            m_detailedResultTextEdit->appendPlainText("🔄 Tarama devam ediyor - lütfen bekleyin");
            m_detailedResultTextEdit->appendPlainText("Tarama motorları dosyayı analiz ediyor...");
        } else {
            m_detailedResultTextEdit->appendPlainText(QString("ℹ️ Tarama durumu: %1").arg(status));
        }
        
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // Tarih bilgisi
    if (attributes.contains("date")) {
        QDateTime analysisDate = QDateTime::fromSecsSinceEpoch(attributes["date"].toInt());
        m_detailedResultTextEdit->appendPlainText(QString("📅 Analiz Tarihi: %1").arg(
            analysisDate.toString("yyyy-MM-dd hh:mm:ss")
        ));
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // Genel tarama istatistikleri
    if (attributes.contains("stats") && !attributes["stats"].isNull()) {
        QJsonObject stats = attributes["stats"].toObject();
        
        m_detailedResultTextEdit->appendPlainText("📈 TARAMA İSTATİSTİKLERİ");
        m_detailedResultTextEdit->appendPlainText("==================================");
        m_detailedResultTextEdit->appendPlainText(QString("✅ Temiz/Zararsız: %1").arg(stats.contains("harmless") ? stats["harmless"].toInt() : 0));
        m_detailedResultTextEdit->appendPlainText(QString("⚠️ Şüpheli: %1").arg(stats.contains("suspicious") ? stats["suspicious"].toInt() : 0));
        m_detailedResultTextEdit->appendPlainText(QString("❌ Zararlı: %1").arg(stats.contains("malicious") ? stats["malicious"].toInt() : 0));
        m_detailedResultTextEdit->appendPlainText(QString("❓ Tespit Edilmemiş: %1").arg(stats.contains("undetected") ? stats["undetected"].toInt() : 0));
        m_detailedResultTextEdit->appendPlainText(QString("⏱️ Zaman Aşımı: %1").arg(stats.contains("timeout") ? stats["timeout"].toInt() : 0));
        m_detailedResultTextEdit->appendPlainText(QString("❌ Başarısız: %1").arg(stats.contains("failure") ? stats["failure"].toInt() : 0));
        
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // Detaylı AV motorları sonuçları (Analysis objelerinde)
    if (attributes.contains("results") && !attributes["results"].toObject().isEmpty()) {
        QJsonObject results = attributes["results"].toObject();
        
        m_detailedResultTextEdit->appendPlainText("🔍 DETAYLI ANTİVİRÜS SONUÇLARI");
        m_detailedResultTextEdit->appendPlainText("==================================");
        
        QStringList avNames = results.keys();
        std::sort(avNames.begin(), avNames.end()); // Alfabetik sırala
        
        int positiveCount = 0;
        for (const QString &avName : avNames) {
            QJsonObject avResult = results[avName].toObject();
            QString category = avResult.contains("category") ? avResult["category"].toString() : "N/A";
            QString result = avResult.contains("result") ? avResult["result"].toString() : "";
            QString version = avResult.contains("engine_version") ? avResult["engine_version"].toString() : "";
            
            QString status;
            if (category == "malicious") {
                status = "❌ ZARARLI";
                positiveCount++;
            } else if (category == "suspicious") {
                status = "⚠️ ŞÜPHELİ";
                positiveCount++;
            } else if (category == "harmless") {
                status = "✅ TEMİZ";
            } else if (category == "undetected") {
                status = "🟢 TEMİZ";
            } else {
                status = "❓ BELİRSİZ";
            }
            
            QString resultLine = QString("%1 %2").arg(avName, status);
            if (!version.isEmpty()) {
                resultLine += QString(" (v%1)").arg(version);
            }
            if (!result.isEmpty()) {
                resultLine += QString(": %1").arg(result);
            }
            
            m_detailedResultTextEdit->appendPlainText(resultLine);
        }
        
        if (!avNames.isEmpty()) {
            double detection_rate = (double)positiveCount / avNames.size() * 100.0;
            m_detailedResultTextEdit->appendPlainText(QString("\nTespit Oranı: %1/%2 (%3%)").arg(positiveCount).arg(avNames.size()).arg(detection_rate, 0, 'f', 1));
        }
        
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // Detaylı AV motorları sonuçları (File objelerinde)
    else if (dataType == "file" && attributes.contains("last_analysis_results") && !attributes["last_analysis_results"].toObject().isEmpty()) {
        QJsonObject avResults = attributes["last_analysis_results"].toObject();
        m_detailedResultTextEdit->appendPlainText("🔍 DETAYLI ANTİVİRÜS SONUÇLARI");
        m_detailedResultTextEdit->appendPlainText("==================================");
        
        QStringList avNames = avResults.keys();
        std::sort(avNames.begin(), avNames.end());  // Alfabetik sırala
        
        int positiveCount = 0;
        for (const QString &avName : avNames) {
            QJsonObject avResult = avResults[avName].toObject();
            QString category = avResult["category"].toString();
            QString avVersion = avResult.contains("engine_version") ? avResult["engine_version"].toString() : "";
            QString resultText = avResult.contains("result") ? avResult["result"].toString() : "";
            
            QString statusIcon;
            if (category == "malicious") {
                statusIcon = "❌ ZARARLI";
                positiveCount++;
            } else if (category == "suspicious") {
                statusIcon = "⚠️ ŞÜPHELİ";
                positiveCount++;
            } else if (category == "undetected" || category == "harmless") {
                statusIcon = "🟢 TEMİZ";
            } else {
                statusIcon = "⚪ BELİRSİZ";
            }
            
            QString resultLine = QString("%1: %2").arg(avName, statusIcon);
            if (!avVersion.isEmpty()) {
                resultLine += QString(" (v%1)").arg(avVersion);
            }
            if (!resultText.isEmpty()) {
                resultLine += QString(" - %1").arg(resultText);
            }
            
            m_detailedResultTextEdit->appendPlainText(resultLine);
        }
        
        if (!avNames.isEmpty()) {
            double detection_rate = (double)positiveCount / avNames.size() * 100.0;
            m_detailedResultTextEdit->appendPlainText(QString("\nTespit Oranı: %1/%2 (%3%)").arg(positiveCount).arg(avNames.size()).arg(detection_rate, 0, 'f', 1));
        }
        
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // File tipi ve diğer bilgiler (file response'dan gelen bilgiler)
    if (dataType == "file") {
        if (attributes.contains("type_description") && !attributes["type_description"].isNull()) {
            m_detailedResultTextEdit->appendPlainText(QString("📁 Dosya Türü: %1").arg(attributes["type_description"].toString()));
            m_detailedResultTextEdit->appendPlainText("");
        }
        
        if (attributes.contains("meaningful_name") && !attributes["meaningful_name"].isNull()) {
            m_detailedResultTextEdit->appendPlainText(QString("📝 Anlamlı İsim: %1").arg(attributes["meaningful_name"].toString()));
            m_detailedResultTextEdit->appendPlainText("");
        }
        
        // Dosya davranışsal analiz sonuçları (sandbox)
        if (attributes.contains("sandbox_verdicts") && !attributes["sandbox_verdicts"].isNull()) {
            QJsonObject sandboxResults = attributes["sandbox_verdicts"].toObject();
            
            m_detailedResultTextEdit->appendPlainText("🧪 DAVRANIŞSAL ANALİZ SONUÇLARI");
            m_detailedResultTextEdit->appendPlainText("==================================");
            
            QStringList sandboxNames = sandboxResults.keys();
            for (const QString &sandboxName : sandboxNames) {
                QJsonObject sandboxData = sandboxResults[sandboxName].toObject();
                QString category = sandboxData.contains("category") ? sandboxData["category"].toString() : "unknown";
                QString sandboxVerdict;
                
                if (category == "malicious") {
                    sandboxVerdict = "❌ ZARARLI";
                } else if (category == "suspicious") {
                    sandboxVerdict = "⚠️ ŞÜPHELİ";
                } else if (category == "harmless") {
                    sandboxVerdict = "✅ TEMİZ";
                } else {
                    sandboxVerdict = "❓ BELİRSİZ";
                }
                
                m_detailedResultTextEdit->appendPlainText(QString("%1: %2").arg(sandboxName, sandboxVerdict));
            }
            
            m_detailedResultTextEdit->appendPlainText("");
        }
        
        // Topluluk değerlendirmesi
        if (attributes.contains("total_votes") && !attributes["total_votes"].isNull()) {
            QJsonObject votes = attributes["total_votes"].toObject();
            int harmlessVotes = votes.contains("harmless") ? votes["harmless"].toInt() : 0;
            int maliciousVotes = votes.contains("malicious") ? votes["malicious"].toInt() : 0;
            
            if (harmlessVotes > 0 || maliciousVotes > 0) {
                m_detailedResultTextEdit->appendPlainText("👥 TOPLULUK DEĞERLENDİRMESİ");
                m_detailedResultTextEdit->appendPlainText("==================================");
                m_detailedResultTextEdit->appendPlainText(QString("👍 Güvenli Oylar: %1").arg(harmlessVotes));
                m_detailedResultTextEdit->appendPlainText(QString("👎 Zararlı Oylar: %1").arg(maliciousVotes));
                
                int totalVotes = harmlessVotes + maliciousVotes;
                double harmlessPercentage = (double)harmlessVotes / totalVotes * 100.0;
                double maliciousPercentage = (double)maliciousVotes / totalVotes * 100.0;
                
                m_detailedResultTextEdit->appendPlainText(QString("Güvenli Oy Yüzdesi: %1%").arg(harmlessPercentage, 0, 'f', 1));
                m_detailedResultTextEdit->appendPlainText(QString("Zararlı Oy Yüzdesi: %1%").arg(maliciousPercentage, 0, 'f', 1));
                
                m_detailedResultTextEdit->appendPlainText("");
            }
        }
    }
    
    // Link to VirusTotal UI
    if (data.contains("links") && data["links"].toObject().contains("self")) {
        QString selfLink = data["links"].toObject()["self"].toString();
        QString vtGuiLink = selfLink.replace("api/v3/", "gui/");
        
        m_detailedResultTextEdit->appendPlainText("\n🔍 VIRUSTOTAL WEB'DE GÖRÜNTÜLE");
        m_detailedResultTextEdit->appendPlainText("==================================");
        m_detailedResultTextEdit->appendPlainText(vtGuiLink);
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    m_detailedResultTextEdit->appendPlainText("\n=============== RAPOR SONU ================");
}