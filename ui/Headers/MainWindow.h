#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include <QTabWidget>
#include <QToolBar>
#include <QPushButton>
#include <QLabel>
#include <QStatusBar>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QSettings>
#include <memory>

// Forward declarations
class ScanWidget;
class HistoryWidget;
class SettingsWidget;
class DashboardWidget;
class ServiceLocator;
class ScanManager;
class IDbManager;

/**
 * @brief Ana pencere sınıfı
 * Uygulamanın ana penceresini ve içerdiği bileşenleri yönetir
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    /**
     * @brief Yapıcı metod
     * @param parent Üst QWidget
     */
    explicit MainWindow(QWidget *parent = nullptr);
    
    /**
     * @brief Destructor
     */
    ~MainWindow();

private slots:
    /**
     * @brief Dashboard sayfasını gösterir
     */
    void showDashboard();
    
    /**
     * @brief Tarama sayfasını gösterir
     */
    void showScan();
    
    /**
     * @brief Geçmiş sayfasını gösterir
     */
    void showHistory();
    
    /**
     * @brief Ayarlar sayfasını gösterir
     */
    void showSettings();
    
    /**
     * @brief Sistem tepsisi simgesi tıklandığında çağrılır
     * @param reason Tıklama nedeni
     */
    void trayIconActivated(QSystemTrayIcon::ActivationReason reason);

protected:
    /**
     * @brief Pencere kapatma olayı
     * @param event Kapatma olayı
     */
    void closeEvent(QCloseEvent *event) override;

private:
    /**
     * @brief UI bileşenlerini oluşturur
     */
    void createUI();
    
    /**
     * @brief Araç çubuğunu oluşturur
     */
    void createToolbar();
    
    /**
     * @brief Sinyal-slot bağlantılarını kurar
     */
    void setupConnections();
    
    /**
     * @brief Sistem tepsisi simgesini oluşturur
     */
    void setupTrayIcon();
    
    /**
     * @brief Servis bağlantılarını oluşturur
     */
    void setupServices();

    // UI bileşenleri
    QToolBar* m_toolbar;
    QStackedWidget* m_stackedWidget;
    QStatusBar* m_statusBar;
    QSystemTrayIcon* m_trayIcon;
    QMenu* m_trayMenu;
    
    // Sayfa widget'ları
    DashboardWidget* m_dashboardWidget;
    ScanWidget* m_scanWidget;
    HistoryWidget* m_historyWidget;
    SettingsWidget* m_settingsWidget;
    
    // Araç çubuğu butonları
    QPushButton* m_dashboardBtn;
    QPushButton* m_scanBtn;
    QPushButton* m_historyBtn;
    QPushButton* m_settingsBtn;
    
    // Settings
    QSettings m_settings;
    
    // Servis nesneleri
    ScanManager* m_scanManager;
    IDbManager* m_dbManager;
};

#endif // MAINWINDOW_H