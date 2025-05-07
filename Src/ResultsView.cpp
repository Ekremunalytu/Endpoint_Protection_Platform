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
    
    // QSS'i CSS niteliklerini ayarlamak yerine objectName atayarak kullanıyoruz
    textEdit->setObjectName("resultsTextEdit");
    
    // Satır sayısı için sol kenar boşluğu - bu özellikler hala kod içerisinde ayarlanabilir
    textEdit->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    textEdit->document()->setDocumentMargin(15);
}

void ResultsView::showNormalResults(const QJsonObject& response)
{
    if (!m_resultTextEdit) return;
    
    // Null check
    if (response.isEmpty()) {
        m_resultTextEdit->appendPlainText("❌ Error: API response is empty or invalid.");
        return;
    }

    // Check data object
    if (!response.contains("data") || response["data"].isNull()) {
        m_resultTextEdit->appendPlainText("❌ Sorry, file scan results could not be retrieved.");
        return;
    }

    QJsonObject data = response["data"].toObject();
    
    // Check attributes object
    if (!data.contains("attributes") || data["attributes"].isNull()) {
        m_resultTextEdit->appendPlainText("❌ File analysis results not found.");
        return;
    }

    QJsonObject attributes = data["attributes"].toObject();
    
    // Header
    m_resultTextEdit->appendPlainText("=== File Security Report ===\n");
    
    // Display file information
    if (attributes.contains("meaningful_name") && !attributes["meaningful_name"].isNull()) {
        m_resultTextEdit->appendPlainText(QString("📝 File Name: %1").arg(attributes["meaningful_name"].toString()));
    }
    if (attributes.contains("type_description") && !attributes["type_description"].isNull()) {
        m_resultTextEdit->appendPlainText(QString("📁 File Type: %1").arg(attributes["type_description"].toString()));
    }
    if (attributes.contains("size") && !attributes["size"].isNull()) {
        double sizeInMB = attributes["size"].toDouble() / (1024 * 1024);
        m_resultTextEdit->appendPlainText(QString("💾 Size: %1 MB").arg(sizeInMB, 0, 'f', 2));
    }

    // Community Assessment
    if (attributes.contains("total_votes") && !attributes["total_votes"].isNull()) {
        QJsonObject votes = attributes["total_votes"].toObject();
        int harmlessVotes = votes.contains("harmless") ? votes["harmless"].toInt() : 0;
        int maliciousVotes = votes.contains("malicious") ? votes["malicious"].toInt() : 0;
        
        if (harmlessVotes > 0 || maliciousVotes > 0) {
            m_resultTextEdit->appendPlainText("\n👥 COMMUNITY COMMENTS");
            m_resultTextEdit->appendPlainText("------------------");
            m_resultTextEdit->appendPlainText(QString("👍 %1 users think this file is safe").arg(harmlessVotes));
            m_resultTextEdit->appendPlainText(QString("👎 %1 users think this file is malicious").arg(maliciousVotes));
        }
    }

    // Recommendations
    m_resultTextEdit->appendPlainText("\n💡 RECOMMENDATIONS");
    m_resultTextEdit->appendPlainText("------------------");

    // General Assessment - Safety check
    if (attributes.contains("stats") && !attributes["stats"].isNull()) {
        QJsonObject stats = attributes["stats"].toObject();
        int malicious = stats.contains("malicious") ? stats["malicious"].toInt() : 0;
        int suspicious = stats.contains("suspicious") ? stats["suspicious"].toInt() : 0;
        
        // Security status
        if (malicious > 0) {
            m_resultTextEdit->appendPlainText("⛔ DANGER STATUS");
            m_resultTextEdit->appendPlainText("------------------");
            m_resultTextEdit->appendPlainText("This file may contain malware!");
            m_resultTextEdit->appendPlainText(QString("🔴 %1 antivirus programs detected this file as malicious.").arg(malicious));
            
            if (suspicious > 0) {
                m_resultTextEdit->appendPlainText(QString("🟠 %1 antivirus programs found this file suspicious.").arg(suspicious));
            }
            
            m_resultTextEdit->appendPlainText("❌ We recommend NOT using this file.");
            m_resultTextEdit->appendPlainText("❌ Delete or quarantine this file immediately.");
        } else if (suspicious > 0) {
            m_resultTextEdit->appendPlainText("⚠️ CAUTION STATUS");
            m_resultTextEdit->appendPlainText("------------------");
            m_resultTextEdit->appendPlainText("This file is flagged as suspicious!");
            m_resultTextEdit->appendPlainText(QString("🟠 %1 antivirus programs found this file suspicious.").arg(suspicious));
            m_resultTextEdit->appendPlainText("⚠️ If you obtained this file from a trusted source, you may use it.");
            m_resultTextEdit->appendPlainText("⚠️ If you're not sure, consult a security expert before executing the file.");
        } else {
            m_resultTextEdit->appendPlainText("✅ You can use this file safely.");
            m_resultTextEdit->appendPlainText("💡 We still recommend using an up-to-date antivirus.");
        }
    }
}

void ResultsView::showDetailedResults(const QJsonObject& response)
{
    if (!m_detailedResultTextEdit) return;
    m_detailedResultTextEdit->clear();
    
    // Null check
    if (response.isEmpty()) {
        m_detailedResultTextEdit->appendPlainText("❌ Error: API response is empty or invalid.");
        return;
    }

    // Check data object
    if (!response.contains("data") || response["data"].isNull()) {
        m_detailedResultTextEdit->appendPlainText("❌ Sorry, detailed file scan results could not be retrieved.");
        return;
    }

    QJsonObject data = response["data"].toObject();
    QString dataType = data.contains("type") ? data["type"].toString() : "";
    
    // Header and general information
    m_detailedResultTextEdit->appendPlainText("=============== DETAILED ANALYSIS REPORT ================\n");
    
    // Check attributes object
    if (!data.contains("attributes") || data["attributes"].isNull()) {
        m_detailedResultTextEdit->appendPlainText("❌ Detailed file analysis results not found.");
        return;
    }

    QJsonObject attributes = data["attributes"].toObject();
    
    // Add first analysis ID
    QString analysisId = data["id"].toString();
    if (!analysisId.isEmpty()) {
        m_detailedResultTextEdit->appendPlainText(QString("🔍 Analysis ID: %1").arg(analysisId));
        m_detailedResultTextEdit->appendPlainText("==================================\n");
    }
    
    // META - File Information
    // File info from meta section (available in both analysis and file responses)
    QJsonObject fileInfo;
    if (response.contains("meta") && response["meta"].toObject().contains("file_info")) {
        fileInfo = response["meta"].toObject()["file_info"].toObject();
    } else if (attributes.contains("meta") && attributes["meta"].toObject().contains("file_info")) {
        fileInfo = attributes["meta"].toObject()["file_info"].toObject();
    }
    
    if (!fileInfo.isEmpty()) {
        m_detailedResultTextEdit->appendPlainText("📄 FILE INFORMATION");
        m_detailedResultTextEdit->appendPlainText("==================================");
        
        if (fileInfo.contains("sha256"))
            m_detailedResultTextEdit->appendPlainText(QString("🔒 SHA-256: %1").arg(fileInfo["sha256"].toString()));
        if (fileInfo.contains("sha1"))
            m_detailedResultTextEdit->appendPlainText(QString("🔒 SHA-1: %1").arg(fileInfo["sha1"].toString()));
        if (fileInfo.contains("md5"))
            m_detailedResultTextEdit->appendPlainText(QString("🔒 MD5: %1").arg(fileInfo["md5"].toString()));
        if (fileInfo.contains("size"))
            m_detailedResultTextEdit->appendPlainText(QString("💾 Size: %1 bytes").arg(fileInfo["size"].toInt()));
        
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // Scan Status
    if (attributes.contains("status")) {
        QString status = attributes["status"].toString();
        m_detailedResultTextEdit->appendPlainText("🔄 SCAN STATUS");
        m_detailedResultTextEdit->appendPlainText("==================================");
        
        if (status == "completed") {
            m_detailedResultTextEdit->appendPlainText("✅ Scan completed");
        } else if (status == "queued") {
            m_detailedResultTextEdit->appendPlainText("⏳ Scan queued - results not ready yet");
            m_detailedResultTextEdit->appendPlainText("System is waiting for scan queue...");
        } else if (status == "in-progress") {
            m_detailedResultTextEdit->appendPlainText("🔄 Scan in progress - please wait");
            m_detailedResultTextEdit->appendPlainText("Scanning engines are analyzing the file...");
        } else {
            m_detailedResultTextEdit->appendPlainText(QString("ℹ️ Scan status: %1").arg(status));
        }
        
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // Date information
    if (attributes.contains("date")) {
        QDateTime analysisDate = QDateTime::fromSecsSinceEpoch(attributes["date"].toInt());
        m_detailedResultTextEdit->appendPlainText(QString("📅 Analysis Date: %1").arg(
            analysisDate.toString("yyyy-MM-dd hh:mm:ss")
        ));
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // General scan statistics
    if (attributes.contains("stats") && !attributes["stats"].isNull()) {
        QJsonObject stats = attributes["stats"].toObject();
        
        m_detailedResultTextEdit->appendPlainText("📈 SCAN STATISTICS");
        m_detailedResultTextEdit->appendPlainText("==================================");
        m_detailedResultTextEdit->appendPlainText(QString("✅ Clean/Harmless: %1").arg(stats.contains("harmless") ? stats["harmless"].toInt() : 0));
        m_detailedResultTextEdit->appendPlainText(QString("⚠️ Suspicious: %1").arg(stats.contains("suspicious") ? stats["suspicious"].toInt() : 0));
        m_detailedResultTextEdit->appendPlainText(QString("❌ Malicious: %1").arg(stats.contains("malicious") ? stats["malicious"].toInt() : 0));
        m_detailedResultTextEdit->appendPlainText(QString("❓ Undetected: %1").arg(stats.contains("undetected") ? stats["undetected"].toInt() : 0));
        m_detailedResultTextEdit->appendPlainText(QString("⏱️ Timeout: %1").arg(stats.contains("timeout") ? stats["timeout"].toInt() : 0));
        m_detailedResultTextEdit->appendPlainText(QString("❌ Failure: %1").arg(stats.contains("failure") ? stats["failure"].toInt() : 0));
        
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // Detailed AV engine results (in Analysis objects)
    if (attributes.contains("results") && !attributes["results"].toObject().isEmpty()) {
        QJsonObject results = attributes["results"].toObject();
        
        m_detailedResultTextEdit->appendPlainText("🔍 DETAILED ANTIVIRUS RESULTS");
        m_detailedResultTextEdit->appendPlainText("==================================");
        
        QStringList avNames = results.keys();
        std::sort(avNames.begin(), avNames.end()); // Alphabetical sorting
        
        int positiveCount = 0;
        for (const QString &avName : avNames) {
            QJsonObject avResult = results[avName].toObject();
            QString category = avResult.contains("category") ? avResult["category"].toString() : "N/A";
            QString result = avResult.contains("result") ? avResult["result"].toString() : "";
            QString version = avResult.contains("engine_version") ? avResult["engine_version"].toString() : "";
            
            QString status;
            if (category == "malicious") {
                status = "❌ MALICIOUS";
                positiveCount++;
            } else if (category == "suspicious") {
                status = "⚠️ SUSPICIOUS";
                positiveCount++;
            } else if (category == "harmless") {
                status = "✅ CLEAN";
            } else if (category == "undetected") {
                status = "🟢 CLEAN";
            } else {
                status = "❓ UNKNOWN";
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
            m_detailedResultTextEdit->appendPlainText(QString("\nDetection Rate: %1/%2 (%3%)").arg(positiveCount).arg(avNames.size()).arg(detection_rate, 0, 'f', 1));
        }
        
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // Detailed AV engine results (in File objects)
    else if (dataType == "file" && attributes.contains("last_analysis_results") && !attributes["last_analysis_results"].toObject().isEmpty()) {
        QJsonObject avResults = attributes["last_analysis_results"].toObject();
        m_detailedResultTextEdit->appendPlainText("🔍 DETAILED ANTIVIRUS RESULTS");
        m_detailedResultTextEdit->appendPlainText("==================================");
        
        QStringList avNames = avResults.keys();
        std::sort(avNames.begin(), avNames.end());  // Alphabetical sorting
        
        int positiveCount = 0;
        for (const QString &avName : avNames) {
            QJsonObject avResult = avResults[avName].toObject();
            QString category = avResult["category"].toString();
            QString avVersion = avResult.contains("engine_version") ? avResult["engine_version"].toString() : "";
            QString resultText = avResult.contains("result") ? avResult["result"].toString() : "";
            
            QString statusIcon;
            if (category == "malicious") {
                statusIcon = "❌ MALICIOUS";
                positiveCount++;
            } else if (category == "suspicious") {
                statusIcon = "⚠️ SUSPICIOUS";
                positiveCount++;
            } else if (category == "undetected" || category == "harmless") {
                statusIcon = "🟢 CLEAN";
            } else {
                statusIcon = "⚪ UNKNOWN";
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
            m_detailedResultTextEdit->appendPlainText(QString("\nDetection Rate: %1/%2 (%3%)").arg(positiveCount).arg(avNames.size()).arg(detection_rate, 0, 'f', 1));
        }
        
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    // File type and other info (from file response)
    if (dataType == "file") {
        if (attributes.contains("type_description") && !attributes["type_description"].isNull()) {
            m_detailedResultTextEdit->appendPlainText(QString("📁 File Type: %1").arg(attributes["type_description"].toString()));
            m_detailedResultTextEdit->appendPlainText("");
        }
        
        if (attributes.contains("meaningful_name") && !attributes["meaningful_name"].isNull()) {
            m_detailedResultTextEdit->appendPlainText(QString("📝 Meaningful Name: %1").arg(attributes["meaningful_name"].toString()));
            m_detailedResultTextEdit->appendPlainText("");
        }
        
        // File behavioral analysis results (sandbox)
        if (attributes.contains("sandbox_verdicts") && !attributes["sandbox_verdicts"].isNull()) {
            QJsonObject sandboxResults = attributes["sandbox_verdicts"].toObject();
            
            m_detailedResultTextEdit->appendPlainText("🧪 BEHAVIORAL ANALYSIS RESULTS");
            m_detailedResultTextEdit->appendPlainText("==================================");
            
            QStringList sandboxNames = sandboxResults.keys();
            for (const QString &sandboxName : sandboxNames) {
                QJsonObject sandboxData = sandboxResults[sandboxName].toObject();
                QString category = sandboxData.contains("category") ? sandboxData["category"].toString() : "unknown";
                QString sandboxVerdict;
                
                if (category == "malicious") {
                    sandboxVerdict = "❌ MALICIOUS";
                } else if (category == "suspicious") {
                    sandboxVerdict = "⚠️ SUSPICIOUS";
                } else if (category == "harmless") {
                    sandboxVerdict = "✅ CLEAN";
                } else {
                    sandboxVerdict = "❓ UNKNOWN";
                }
                
                m_detailedResultTextEdit->appendPlainText(QString("%1: %2").arg(sandboxName, sandboxVerdict));
            }
            
            m_detailedResultTextEdit->appendPlainText("");
        }
        
        // Community assessment
        if (attributes.contains("total_votes") && !attributes["total_votes"].isNull()) {
            QJsonObject votes = attributes["total_votes"].toObject();
            int harmlessVotes = votes.contains("harmless") ? votes["harmless"].toInt() : 0;
            int maliciousVotes = votes.contains("malicious") ? votes["malicious"].toInt() : 0;
            
            if (harmlessVotes > 0 || maliciousVotes > 0) {
                m_detailedResultTextEdit->appendPlainText("👥 COMMUNITY ASSESSMENT");
                m_detailedResultTextEdit->appendPlainText("==================================");
                m_detailedResultTextEdit->appendPlainText(QString("👍 Safe Votes: %1").arg(harmlessVotes));
                m_detailedResultTextEdit->appendPlainText(QString("👎 Malicious Votes: %1").arg(maliciousVotes));
                
                int totalVotes = harmlessVotes + maliciousVotes;
                double harmlessPercentage = (double)harmlessVotes / totalVotes * 100.0;
                double maliciousPercentage = (double)maliciousVotes / totalVotes * 100.0;
                
                m_detailedResultTextEdit->appendPlainText(QString("Safe Vote Percentage: %1%").arg(harmlessPercentage, 0, 'f', 1));
                m_detailedResultTextEdit->appendPlainText(QString("Malicious Vote Percentage: %1%").arg(maliciousPercentage, 0, 'f', 1));
                
                m_detailedResultTextEdit->appendPlainText("");
            }
        }
    }
    
    // Link to VirusTotal UI
    if (data.contains("links") && data["links"].toObject().contains("self")) {
        QString selfLink = data["links"].toObject()["self"].toString();
        QString vtGuiLink = selfLink.replace("api/v3/", "gui/");
        
        m_detailedResultTextEdit->appendPlainText("\n🔍 VIEW ON VIRUSTOTAL WEB");
        m_detailedResultTextEdit->appendPlainText("==================================");
        m_detailedResultTextEdit->appendPlainText(vtGuiLink);
        m_detailedResultTextEdit->appendPlainText("");
    }
    
    m_detailedResultTextEdit->appendPlainText("\n=============== END OF REPORT ================");
}