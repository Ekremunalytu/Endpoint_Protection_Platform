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

class ApiManager;
class YaraRuleManager;
class CdrManager;
class SandboxManager;

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
    void performCdrScan(const QString& filePath);
    void performSandboxScan(const QString& filePath);

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