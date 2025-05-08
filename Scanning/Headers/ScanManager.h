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
#include <memory>
#include <functional>
#include <QProgressDialog>
#include <QMutex>
#include <QtConcurrent>

// Arayüz başlık dosyaları
#include "Interfaces/Headers/IApiManager.h"
#include "Interfaces/Headers/IYaraRuleManager.h"
#include "Interfaces/Headers/ICdrManager.h"
#include "Interfaces/Headers/ISandboxManager.h"
#include "Interfaces/Headers/IDbManager.h"
#include "ThreadPool.h"

class ScanManager : public QObject
{
    Q_OBJECT

public:
    // Bağımlılıkları dışarıdan alan yapıcı metod
    explicit ScanManager(
        IApiManager* apiManager,
        IYaraRuleManager* yaraManager,
        ICdrManager* cdrManager,
        ISandboxManager* sandboxManager,
        IDbManager* dbManager,
        QObject *parent = nullptr
    );
    
    ~ScanManager();

    // UI bileşenlerini ayarlama metotları
    void setTextEdit(QPlainTextEdit* resultTextEdit);
    void setLogTextEdit(QPlainTextEdit* logTextEdit);
    void setStatusBar(QStatusBar* statusBar);

    // Tarama işlemleri
    void performOfflineScan(const QString& filePath);
    void performOnlineScan(const QString& filePath);
    bool performCdrScan(const QString& filePath, bool async = true);
    bool performSandboxScan(const QString& filePath, bool async = true);
    
    // Servis durum kontrolleri
    bool isDbInitialized() const;
    bool isCdrInitialized() const;
    bool isSandboxInitialized() const;

    // Docker imaj ayarları
    void setCdrImageName(const QString& imageName);
    void setSandboxImageName(const QString& imageName);
    QString getCurrentCdrImageName() const;
    QString getCurrentSandboxImageName() const;
    QStringList getAvailableCdrImages() const;
    QStringList getAvailableSandboxImages() const;

    // İşlem durumunu sorgula
    bool isOperationInProgress() const { return m_operationInProgress; }

signals:
    void dockerImageSelectionRequired(const QString &serviceType);
    void operationStarted(const QString& operationType);
    void operationCompleted(const QString& operationType, bool success);
    void progressUpdated(int percentage);

    /**
     * @brief Tarama ilerlemesi güncellendiğinde sinyal
     * @param progress 0-100 arası ilerleme yüzdesi
     */
    void scanProgressUpdated(int progress);
    
    /**
     * @brief Tarama tamamlandığında sinyal
     * @param scanType Tarama türü (Offline, VirusTotal, CDR, Sandbox)
     * @param filePath Taranan dosyanın yolu
     * @param result Tarama sonucu (JSON, text vb.)
     * @param isClean Dosyanın temiz olup olmadığı
     */
    void scanCompleted(const QString& scanType, const QString& filePath, const QString& result, bool isClean);
    
    /**
     * @brief Tarama sırasında hata oluştuğunda sinyal
     * @param error Hata mesajı
     */
    void scanError(const QString& error);

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

    // Manager nesneleri - artık arayüz pointerları kullanılıyor
    IApiManager* m_apiManager;
    IYaraRuleManager* m_yaraManager;
    ICdrManager* m_cdrManager;
    ISandboxManager* m_sandboxManager;
    IDbManager* m_dbManager;
    
    // Auto-refresh timer
    QTimer* m_refreshTimer;
    QString m_currentAnalysisId;
    int m_refreshAttempts;
    
    // Operasyon durumu
    bool m_operationInProgress;
    QMutex m_operationMutex;

    static constexpr int MAX_REFRESH_ATTEMPTS = 10;
    
    // Helper methods
    void fetchAnalysisResults(const QString& analysisId);

    // Asenkron CDR ve Sandbox operasyonları için yardımcı metotlar
    void executeCdrScanAsync(const QString& filePath);
    void executeSandboxScanAsync(const QString& filePath);
    void updateUiForOperationStart(const QString& operationType, const QString& filePath);
    void updateUiForOperationComplete(const QString& operationType, bool success, const QString& details = QString());

    /**
     * @brief Tarama sonucunu veritabanına kaydeder
     * @param scanType Tarama türü
     * @param filePath Taranan dosyanın yolu
     * @param result Tarama sonucu
     * @param isClean Dosyanın temiz olup olmadığı
     */
    void logScanResult(const QString& scanType, const QString& filePath, const QString& result, bool isClean);
};

#endif // SCANMANAGER_H