#ifndef SCANMANAGER_H
#define SCANMANAGER_H

#include <QObject>
#include <QString>
#include <QPlainTextEdit>
#include <QStatusBar>
#include <QDateTime>
#include <QJsonObject>
#include <QTimer>
#include <vector>
#include <string>

#include "ApiManager.h"
#include "YaraRuleManager.h"
#include "CdrManager.h"
#include "SandboxManager.h"

class ScanManager : public QObject
{
    Q_OBJECT

public:
    explicit ScanManager(QObject *parent = nullptr);
    ~ScanManager();

    // UI bileşenlerini ayarla
    void setTextEdit(QPlainTextEdit* resultTextEdit);
    void setLogTextEdit(QPlainTextEdit* logTextEdit);
    void setStatusBar(QStatusBar* statusBar);

    // Tarama işlemleri
    void performOfflineScan(const QString& filePath);
    void performOnlineScan(const QString& filePath);
    bool performCdrScan(const QString& filePath);
    bool performSandboxScan(const QString& filePath);
    
    // Servis durum kontrolleri
    bool isDbInitialized() const;
    bool isCdrInitialized() const;
    bool isSandboxInitialized() const;

    // Docker imaj ayarları
    void setCdrImageName(const QString& imageName) {
        if (m_cdrManager) {
            m_cdrManager->setCdrImageName(imageName);
        }
    }
    
    void setSandboxImageName(const QString& imageName) {
        if (m_sandboxManager) {
            m_sandboxManager->setSandboxImageName(imageName);
        }
    }
    
    QString getCurrentCdrImageName() const {
        return m_cdrManager ? m_cdrManager->getCurrentImageName() : QString();
    }
    
    QString getCurrentSandboxImageName() const {
        return m_sandboxManager ? m_sandboxManager->getCurrentImageName() : QString();
    }
    
    QStringList getAvailableCdrImages() const {
        return m_cdrManager ? m_cdrManager->getAvailableCdrImages() : QStringList();
    }
    
    QStringList getAvailableSandboxImages() const {
        return m_sandboxManager ? m_sandboxManager->getAvailableSandboxImages() : QStringList();
    }

signals:
    void dockerImageSelectionRequired(const QString &serviceType);

private slots:
    // API response handlers
    void handleApiResponse(const QJsonObject& response);
    void handleApiError(const QString& errorMessage);
    
    // Auto-refresh handler
    void checkAnalysisStatus();

private:
    QPlainTextEdit* m_resultTextEdit;
    QPlainTextEdit* m_logTextEdit;
    QStatusBar* m_statusBar;

    // Manager nesneleri
    ApiManager* m_apiManager;
    YaraRuleManager* m_yaraManager;
    CdrManager* m_cdrManager;
    SandboxManager* m_sandboxManager;
    
    // Auto-refresh timer
    QTimer* m_refreshTimer;
    QString m_currentAnalysisId;
    int m_refreshAttempts;
    static constexpr int MAX_REFRESH_ATTEMPTS = 10;
    
    // Helper methods
    void fetchAnalysisResults(const QString& analysisId);
};

#endif // SCANMANAGER_H