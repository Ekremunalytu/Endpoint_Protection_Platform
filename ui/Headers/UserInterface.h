#ifndef USERINTERFACE_H
#define USERINTERFACE_H

#include <QMainWindow>
#include <QString>
#include <QAction>
#include <QPlainTextEdit>
#include <QStatusBar>
#include <QProgressDialog>
#include <memory>
#include <mutex>

// Interface ve manager sınıfları
#include "Interfaces/Headers/IApiManager.h"
#include "Interfaces/Headers/IDbManager.h"
#include "Interfaces/Headers/IYaraRuleManager.h"
#include "Interfaces/Headers/ICdrManager.h"
#include "Interfaces/Headers/ISandboxManager.h"
#include "Interfaces/Headers/IDockerManager.h"

// Manager sınıfları
#include "ApiManager.h"
#include "DbManager.h"
#include "YaraRuleManager.h"
#include "ScanManager.h"
#include "ResultsView.h"
#include "DockerUIManager.h"

// Oluşturduğumuz Widget'lar
#include "Widgets/SidebarWidget.h"
#include "Widgets/ScanWidget.h"
#include "Widgets/ResultsWidget.h"

// Forward declarations
class QLabel;
class QProgressDialog;

/**
 * @brief Uygulamanın ana penceresi
 * Tüm UI bileşenlerini ve manager sınıflarını koordine eder
 */
class UserInterface : public QMainWindow {
    Q_OBJECT
public:
    /**
     * @brief Yapıcı metod
     * @param parent Üst widget
     */
    explicit UserInterface(QWidget *parent = nullptr);
    
    /**
     * @brief Destructor - bellek temizliği için
     */
    ~UserInterface();

private slots:
    // API iletişimi için slotlar
    void onApiResponseReceived(const QJsonObject& response);
    void onApiError(const QString& errorMessage);
    void onApiRequestSent(const QString& endpoint);
    
    // Docker yönetimi
    void showContainerDetails();
    
    // İşlem işleyicileri
    void handleOperationStarted(const QString& operationType);
    void handleOperationCompleted(const QString& operationType, bool success);
    void handleProgressUpdated(int percentage);
    
    // Sidebar sayfa değişimi
    void onPageChanged(SidebarWidget::Page page);
    
    // API Key ayarlama
    void onApiKeyButtonClicked();
    
    // Service Status dialog
    void onServiceStatusButtonClicked();

private:
    void createActions();
    void createMenus();
    void createStatusBar();
    void setupProgressDialog();
    void initializeServices();
    void initializeUI();
    
    // Manager sınıfları - akıllı göstericiler ile
    std::shared_ptr<IApiManager> m_apiManager;
    std::shared_ptr<IYaraRuleManager> m_yaraManager;
    std::shared_ptr<ICdrManager> m_cdrManager;
    std::shared_ptr<ISandboxManager> m_sandboxManager;
    std::shared_ptr<IDbManager> m_dbManager;
    std::shared_ptr<IDockerManager> m_dockerManager;
    
    // UI Manager sınıfları
    std::unique_ptr<ScanManager> m_scanManager;
    std::unique_ptr<ResultsView> m_resultsView;
    std::unique_ptr<DockerUIManager> m_dockerUIManager;
    
    // Modern UI bileşenleri
    std::unique_ptr<SidebarWidget> m_sidebarWidget;
    std::unique_ptr<ScanWidget> m_scanWidget;
    std::unique_ptr<ResultsWidget> m_resultsWidget;
    
    // Diğer UI elemanları
    QAction* m_menuAction;
    QAction* m_apiKeyAction;
    QAction* m_dockerAction;
    QAction* m_serviceStatusAction;
    QLabel* m_statusLabel;
    
    // İlerleme göstergesi
    QProgressDialog* m_progressDialog;
    int m_currentProgress;
    std::mutex m_progressMutex; // Thread-safe operasyonlar için mutex
};

#endif // USERINTERFACE_H
