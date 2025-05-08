#include "UI/Headers/MainWindow.h"
#include "Widgets/ScanWidget.h"
#include "Widgets/HistoryWidget.h"
#include "Widgets/SettingsWidget.h"
#include "Widgets/DashboardWidget.h"
#include "Core/Headers/ServiceLocator.h"
#include "Database/Headers/DbManager.h"
#include "Scanning/Headers/ScanManager.h"
#include <QApplication>
#include <QCloseEvent>
#include <QMessageBox>
#include <QIcon>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_settings("EndpointProtection", "EPPlatform")
{
    // Servislerden gerekli bileşenleri al
    setupServices();
    
    // UI bileşenlerini oluştur
    createUI();
    createToolbar();
    setupConnections();
    setupTrayIcon();
    
    // Pencere özelliklerini ayarla
    setWindowTitle(tr("Endpoint Protection Platform"));
    setMinimumSize(800, 600);
    
    // Başlangıçta Dashboard sayfasını göster
    showDashboard();
    
    // Durum çubuğunda başlangıç durumunu göster
    statusBar()->showMessage(tr("Ready"), 3000);
}

MainWindow::~MainWindow()
{
    // Service Locator üzerinden alınan servisler için bir temizleme yapmamıza gerek yok
    // bu servislerin yaşam döngüsü ServiceLocator tarafından yönetilir
    qDebug() << "MainWindow destroyed.";
}

void MainWindow::setupServices()
{
    // Servis Locator üzerinden gerekli servisleri al
    m_dbManager = ServiceLocator::getDbManager();
    if (!m_dbManager) {
        qCritical() << "Failed to get DbManager from ServiceLocator";
        QMessageBox::critical(this, tr("Service Error"), tr("Failed to initialize database services."));
    }
    
    // ScanManager servisini al
    m_scanManager = ServiceLocator::getScanManager();
    if (!m_scanManager) {
        qCritical() << "Failed to get ScanManager from ServiceLocator";
        QMessageBox::critical(this, tr("Service Error"), tr("Failed to initialize scanning services."));
    }
}

void MainWindow::createUI()
{
    // Ana widget container
    m_stackedWidget = new QStackedWidget(this);
    setCentralWidget(m_stackedWidget);
    
    // Dashboard sayfası
    m_dashboardWidget = new DashboardWidget(m_dbManager, this);
    m_stackedWidget->addWidget(m_dashboardWidget);
    
    // Tarama sayfası - ScanManager'ı constructor'a geç
    m_scanWidget = new ScanWidget(m_scanManager, this);
    m_stackedWidget->addWidget(m_scanWidget);
    
    // Geçmiş sayfası - Yeni eklediğimiz HistoryWidget
    m_historyWidget = new HistoryWidget(m_dbManager, this);
    m_stackedWidget->addWidget(m_historyWidget);
    
    // Ayarlar sayfası
    m_settingsWidget = new SettingsWidget(&m_settings, this);
    m_stackedWidget->addWidget(m_settingsWidget);
    
    // Durum çubuğu
    m_statusBar = new QStatusBar(this);
    setStatusBar(m_statusBar);
}

void MainWindow::createToolbar()
{
    m_toolbar = new QToolBar(tr("Main Toolbar"), this);
    m_toolbar->setMovable(false);
    m_toolbar->setFloatable(false);
    m_toolbar->setIconSize(QSize(32, 32));
    
    // Toolbar butonları
    m_dashboardBtn = new QPushButton(tr("Dashboard"), this);
    m_dashboardBtn->setCheckable(true);
    m_dashboardBtn->setObjectName("navButton");
    m_toolbar->addWidget(m_dashboardBtn);
    
    m_scanBtn = new QPushButton(tr("Scan"), this);
    m_scanBtn->setCheckable(true);
    m_scanBtn->setObjectName("navButton");
    m_toolbar->addWidget(m_scanBtn);
    
    m_historyBtn = new QPushButton(tr("History"), this);
    m_historyBtn->setCheckable(true);
    m_historyBtn->setObjectName("navButton");
    m_toolbar->addWidget(m_historyBtn);
    
    m_settingsBtn = new QPushButton(tr("Settings"), this);
    m_settingsBtn->setCheckable(true);
    m_settingsBtn->setObjectName("navButton");
    m_toolbar->addWidget(m_settingsBtn);
    
    addToolBar(Qt::LeftToolBarArea, m_toolbar);
}

void MainWindow::setupConnections()
{
    // Navigasyon butonları bağlantıları
    connect(m_dashboardBtn, &QPushButton::clicked, this, &MainWindow::showDashboard);
    connect(m_scanBtn, &QPushButton::clicked, this, &MainWindow::showScan);
    connect(m_historyBtn, &QPushButton::clicked, this, &MainWindow::showHistory);
    connect(m_settingsBtn, &QPushButton::clicked, this, &MainWindow::showSettings);
    
    // Tarama başlatıldığında statüs çubuğunu güncelle
    connect(m_scanWidget, &ScanWidget::scanStarted, this, [this](bool visible) {
        statusBar()->showMessage(tr("Scan in progress..."));
    });
    
    // ScanManager sinyallerini dinle
    connect(m_scanManager, &ScanManager::scanCompleted, this,
        [this](const QString& scanType, const QString& filePath, const QString& result, bool isClean) {
            statusBar()->showMessage(tr("Scan completed: %1").arg(scanType), 5000);
        });
    
    connect(m_scanManager, &ScanManager::scanError, this,
        [this](const QString& error) {
            statusBar()->showMessage(tr("Scan error: %1").arg(error), 5000);
        });
}

void MainWindow::setupTrayIcon()
{
    m_trayIcon = new QSystemTrayIcon(QIcon(":/images/images/applogo.png"), this);
    m_trayMenu = new QMenu(this);
    
    QAction* showAction = m_trayMenu->addAction(tr("Show"));
    QAction* hideAction = m_trayMenu->addAction(tr("Hide"));
    m_trayMenu->addSeparator();
    QAction* quitAction = m_trayMenu->addAction(tr("Quit"));
    
    connect(showAction, &QAction::triggered, this, &MainWindow::show);
    connect(hideAction, &QAction::triggered, this, &MainWindow::hide);
    connect(quitAction, &QAction::triggered, qApp, &QApplication::quit);
    
    m_trayIcon->setContextMenu(m_trayMenu);
    m_trayIcon->show();
    
    connect(m_trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::trayIconActivated);
}

void MainWindow::showDashboard()
{
    m_stackedWidget->setCurrentWidget(m_dashboardWidget);
    m_dashboardBtn->setChecked(true);
    m_scanBtn->setChecked(false);
    m_historyBtn->setChecked(false);
    m_settingsBtn->setChecked(false);
}

void MainWindow::showScan()
{
    m_stackedWidget->setCurrentWidget(m_scanWidget);
    m_dashboardBtn->setChecked(false);
    m_scanBtn->setChecked(true);
    m_historyBtn->setChecked(false);
    m_settingsBtn->setChecked(false);
}

void MainWindow::showHistory()
{
    m_stackedWidget->setCurrentWidget(m_historyWidget);
    m_dashboardBtn->setChecked(false);
    m_scanBtn->setChecked(false);
    m_historyBtn->setChecked(true);
    m_settingsBtn->setChecked(false);
}

void MainWindow::showSettings()
{
    m_stackedWidget->setCurrentWidget(m_settingsWidget);
    m_dashboardBtn->setChecked(false);
    m_scanBtn->setChecked(false);
    m_historyBtn->setChecked(false);
    m_settingsBtn->setChecked(true);
}

void MainWindow::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::Trigger) {
        if (isVisible()) {
            hide();
        } else {
            show();
            activateWindow();
        }
    }
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    // Ayarlarda minimizeToTray aktif ise, kapatma yerine tepsi simgesine küçült
    if (m_settings.value("General/MinimizeToTray", true).toBool()) {
        hide();
        event->ignore();
    } else {
        event->accept();
    }
}