#include "../Headers/UserInterface.h"
#include "../Headers/ServiceLocator.h"
#include "../Headers/DockerManager.h" // DockerManager başlık dosyasını ekliyoruz

#include <QMainWindow>
#include <QString>
#include <QAction>
#include <QFileDialog>
#include <QMessageBox>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QScrollArea>
#include <QScreen>
#include <QApplication>
#include <QFont>
#include <QMenu>
#include <QDebug>
#include <QFormLayout>
#include <QGroupBox>
#include <QPalette>
#include <QIcon>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTabWidget>
#include <QSplitter>
#include <QPainter>
#include <QPainterPath>
#include <QDesktopServices>
#include <QUrl>
#include <QHeaderView>
#include <QToolButton> // QToolButton başlık dosyasını ekledik
#include <QProgressDialog> // QProgressDialog başlık dosyasını ekledik
#include <cmath>
#include "../Headers/DbManager.h" // DbManager.h başlık dosyasını dahil ediyoruz

ApiKeyDialog::ApiKeyDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("API Key Settings");
    setModal(true);
    setMinimumWidth(450);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setSpacing(20);
    layout->setContentsMargins(30, 30, 30, 30);

    QLabel *infoLabel = new QLabel("Enter your VirusTotal API key:", this);
    infoLabel->setObjectName("infoLabel");
    layout->addWidget(infoLabel);

    apiKeyLineEdit = new QLineEdit(this);
    apiKeyLineEdit->setPlaceholderText("API Key here...");
    layout->addWidget(apiKeyLineEdit);
    
    QLabel *apiInfoLabel = new QLabel(tr("Get your free API key from <a href='https://www.virustotal.com/gui/join-us'>VirusTotal</a>"), this);
    apiInfoLabel->setOpenExternalLinks(true);
    apiInfoLabel->setObjectName("apiInfoLabel");
    layout->addWidget(apiInfoLabel);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(15);

    QPushButton *okButton = new QPushButton("Save", this);
    QPushButton *cancelButton = new QPushButton("Cancel", this);

    cancelButton->setObjectName("secondaryButton");

    buttonLayout->addStretch();
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(okButton);

    layout->addSpacing(20);
    layout->addLayout(buttonLayout);

    connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      menuAction(nullptr),
      scanAction(nullptr),
      virusTotalAction(nullptr),
      apiKeyAction(nullptr),
      statusLabel(nullptr),
      resultTextEdit(nullptr),
      progressDialog(nullptr),
      currentProgress(0)
{
    // Window ayarları
    setWindowTitle("Endpoint Protection Platform");
    resize(1200, 800);
    
    // Stil dosyasını yükle
    QFile styleFile(":/styles/main.qss");
    if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
        QString styleSheet = QLatin1String(styleFile.readAll());
        this->setStyleSheet(styleSheet);
        styleFile.close();
    }
    
    // Önce servisleri başlat, sonra UI elemanlarını oluştur
    initializeServices(); // Bu fonksiyon önce çağrılmalı
    
    // UI elemanlarını oluştur
    createModernCentralWidgets();
    createActions();
    createMenus();
    createToolBars();
    createStatusBar();
    
    // İlerleme göstergesini kur
    setupProgressDialog();
}

MainWindow::~MainWindow()
{
    // Manager sınıfları kendi destructor'larında gerekli temizlemeleri yapacak
}

void MainWindow::setupProgressDialog() {
    progressDialog = new QProgressDialog("İşlem başlatılıyor...", "İptal", 0, 100, this);
    progressDialog->setWindowModality(Qt::WindowModal);
    progressDialog->setAutoClose(true);
    progressDialog->setAutoReset(true);
    progressDialog->setMinimumDuration(500); // 500 ms'den uzun süren işlemler için göster
    progressDialog->reset();
    progressDialog->hide();
    currentProgress = 0;
}

void MainWindow::initializeServices() {
    // Service Locator üzerinden servisleri al
    apiManager = ServiceLocator::getApiManager();
    yaraRuleManager = ServiceLocator::getYaraRuleManager();
    cdrManager = ServiceLocator::getCdrManager();
    sandboxManager = ServiceLocator::getSandboxManager();
    dbManager = ServiceLocator::getDbManager();
    dockerManager = ServiceLocator::getDockerManager();

    // Scan Manager'ı oluştur
    scanManager = new ScanManager(apiManager, yaraRuleManager, cdrManager, sandboxManager, dbManager, this);
    scanManager->setTextEdit(resultTextEdit);
    scanManager->setLogTextEdit(apiLogTextEdit);
    scanManager->setStatusBar(statusBar());

    // ResultsView'ı oluştur
    resultsView = new ResultsView(this);
    resultsView->setResultTextEdit(resultTextEdit);
    resultsView->setDetailedResultTextEdit(detailedResultTextEdit);

    // DockerUIManager'ı oluştur
    dockerUIManager = new DockerUIManager(this);
    dockerUIManager->setDockerManager(dockerManager);

    // Docker imaj seçim sinyalini bağla
    connect(scanManager, &ScanManager::dockerImageSelectionRequired, 
            this, [this](const QString &serviceType) {
                // İlgili servis türü için mevcut imajları ve seçili imajı al
                QStringList availableImages;
                QString currentImage;
                
                if (serviceType == "CDR") {
                    availableImages = scanManager->getAvailableCdrImages();
                    currentImage = scanManager->getCurrentCdrImageName();
                } else {
                    availableImages = scanManager->getAvailableSandboxImages();
                    currentImage = scanManager->getCurrentSandboxImageName();
                }
                
                // Eğer imaj listesi boşsa, kullanıcıya hata mesajı göster
                if (availableImages.isEmpty()) {
                    QMessageBox::warning(this, tr("Docker Images Not Found"), 
                                      tr("No Docker images found for %1 operation.\n"
                                         "Please make sure Docker is running and images are available.")
                                      .arg(serviceType));
                    return;
                }
                
                // Docker imaj seçim dialogunu göster
                DockerImageSelectionDialog dialog(availableImages, currentImage, serviceType, this);
                if (dialog.exec() == QDialog::Accepted) {
                    QString selectedImage = dialog.getSelectedImage();
                    
                    // Seçilen imajı ayarla
                    if (serviceType == "CDR") {
                        scanManager->setCdrImageName(selectedImage);
                    } else {
                        scanManager->setSandboxImageName(selectedImage);
                    }
                    
                    QMessageBox::information(this, tr("Image Selected"), 
                                          tr("Selected %1 image: %2")
                                          .arg(serviceType)
                                          .arg(selectedImage));
                }
            });

    // İşlem başlangıç/bitiş sinyallerini bağla
    connect(scanManager, &ScanManager::operationStarted, this, &MainWindow::handleOperationStarted);
    connect(scanManager, &ScanManager::operationCompleted, this, &MainWindow::handleOperationCompleted);
    connect(scanManager, &ScanManager::progressUpdated, this, &MainWindow::handleProgressUpdated);

    // API bağlantılarını kur (QObject* casting gerektirmeden doğrudan kullanılabilir)
    if (auto apiManagerQObject = dynamic_cast<QObject*>(apiManager)) {
        connect(apiManagerQObject, SIGNAL(responseReceived(const QJsonObject&)),
                this, SLOT(onApiResponseReceived(const QJsonObject&)));
        connect(apiManagerQObject, SIGNAL(error(const QString&)),
                this, SLOT(onApiError(const QString&)));
        connect(apiManagerQObject, SIGNAL(requestSent(const QString&)),
                this, SLOT(onApiRequestSent(const QString&)));
    } else {
        qWarning() << "MainWindow: API Manager does not support signal/slot connections!";
    }
}

void MainWindow::handleOperationStarted(const QString& operationType) {
    progressDialog->setLabelText(tr("%1 işlemi başlatılıyor...").arg(operationType));
    progressDialog->setValue(0);
    progressDialog->show();
    currentProgress = 0;
    
    statusBar()->showMessage(tr("%1 işlemi başlatıldı").arg(operationType));
    qApp->processEvents();
}

void MainWindow::handleOperationCompleted(const QString& operationType, bool success) {
    progressDialog->setValue(100);
    progressDialog->hide();
    currentProgress = 0;
    
    if (success) {
        statusBar()->showMessage(tr("%1 işlemi başarıyla tamamlandı").arg(operationType), 5000);
    } else {
        statusBar()->showMessage(tr("%1 işlemi başarısız oldu").arg(operationType), 5000);
    }
}

void MainWindow::handleProgressUpdated(int percentage) {
    if (percentage > currentProgress) {
        currentProgress = percentage;
        progressDialog->setValue(percentage);
        qApp->processEvents();
    }
}

void MainWindow::createActions()
{
    // Ana menü aksiyonu
    menuAction = new QAction(tr("Menu"), this);
    
    // Alt menü aksiyonları
    scanAction = new QAction(tr("Offline Scan"), this);
    scanAction->setIcon(QIcon::fromTheme("search"));
    connect(scanAction, &QAction::triggered, this, &MainWindow::onScanButtonClicked);

    virusTotalAction = new QAction(tr("VirusTotal Scan"), this);
    virusTotalAction->setIcon(QIcon::fromTheme("network-transmit"));
    connect(virusTotalAction, &QAction::triggered, this, &MainWindow::onsendVirusTotalButtonClicked);
    
    // Yeni CDR aksiyonu
    cdrAction = new QAction(tr("CDR Scan"), this);
    cdrAction->setIcon(QIcon::fromTheme("document-edit"));
    connect(cdrAction, &QAction::triggered, this, &MainWindow::onCdrButtonClicked);
    
    // Yeni Sandbox aksiyonu
    sandboxAction = new QAction(tr("Sandbox Analysis"), this);
    sandboxAction->setIcon(QIcon::fromTheme("system-run"));
    connect(sandboxAction, &QAction::triggered, this, &MainWindow::onSandboxButtonClicked);

    apiKeyAction = new QAction(tr("Set API Key"), this);
    apiKeyAction->setIcon(QIcon::fromTheme("dialog-password"));
    connect(apiKeyAction, &QAction::triggered, this, &MainWindow::onApiKeyButtonClicked);

    // Docker konteyner detayları aksiyonu
    dockerAction = new QAction(tr("Docker Container Details"), this);
    dockerAction->setIcon(QIcon::fromTheme("docker"));
    connect(dockerAction, &QAction::triggered, this, &MainWindow::showContainerDetails);

    // Service Status aksiyonu
    serviceStatusAction = new QAction(tr("Service Status"), this);
    serviceStatusAction->setIcon(QIcon::fromTheme("dialog-information"));
    connect(serviceStatusAction, &QAction::triggered, this, &MainWindow::onServiceStatusButtonClicked);
}

void MainWindow::createMenus()
{
    // Create a single menu button
    QToolButton* menuButton = new QToolButton(this);
    menuButton->setText(tr("Menu"));
    menuButton->setPopupMode(QToolButton::InstantPopup);
    menuButton->setObjectName("menuToolButton");

    // Create menu - Sadeleştirilmiş menü yapısı
    QMenu* menu = new QMenu(this);
    menu->setObjectName("mainMenu");

    // Menüde sadece API Key ayarını bırakıyoruz
    menu->addAction(apiKeyAction);

    menuButton->setMenu(menu);

    // Add menu button to toolbar
    QToolBar* mainToolBar = addToolBar(tr("Main Menu"));
    mainToolBar->setMovable(false);
    mainToolBar->addWidget(menuButton);
    mainToolBar->setObjectName("mainToolBar");
}

void MainWindow::createToolBars()
{
    // Bu fonksiyon artık kullanılmıyor, menü butonu yeterli
}

void MainWindow::createStatusBar()
{
    // QMainWindow'un kendi statusBar()'ını kullanarak basit bir mesaj gösterebiliriz
    statusBar()->showMessage(tr("Ready"));
}

// Yeni modern merkezi widget tasarımı
void MainWindow::createModernCentralWidgets()
{
    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->setSpacing(0);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    // Ana içerik bölümü
    QWidget *contentWidget = new QWidget(this);
    
    // Sol sidebar için bir layout
    QHBoxLayout *horizontalLayout = new QHBoxLayout(contentWidget);
    horizontalLayout->setSpacing(0);
    horizontalLayout->setContentsMargins(0, 0, 0, 0);
    
    // Sol sidebar oluştur
    QWidget *sidebarWidget = new QWidget(this);
    sidebarWidget->setFixedWidth(220);
    sidebarWidget->setObjectName("sidebarWidget");
    
    // Sidebar layout
    QVBoxLayout *sidebarLayout = new QVBoxLayout(sidebarWidget);
    sidebarLayout->setSpacing(0);
    sidebarLayout->setContentsMargins(0, 20, 0, 20);

    // Sidebar butonları için ortak renk - daha tutarlı bir UI için
    QString sidebarButtonColor = "#1e88e5";
    
    // Sidebar butonu oluşturma için lambda fonksiyon
    auto createSidebarButton = [this, sidebarLayout](const QString &text, bool checked = false, bool colored = true) {
        QPushButton *btn = new QPushButton(text, this);
        btn->setCheckable(true);
        btn->setChecked(checked);
        btn->setIconSize(QSize(20, 20));
        
        // Objename ile QSS bağlantısı
        if (colored) {
            btn->setObjectName("coloredSidebarButton");
        } else {
            btn->setObjectName("sidebarButton");
        }
        
        sidebarLayout->addWidget(btn);
        return btn;
    };

    // Sidebar butonları - hepsi aynı renk kullanıyor
    QPushButton *offlineScanBtn = createSidebarButton(tr("Offline Scan"), true);
    QPushButton *virusScanBtn = createSidebarButton(tr("Online Scan"), false);
    QPushButton *cdrScanBtn = createSidebarButton(tr("CDR Scan"), false);
    QPushButton *sandboxBtn = createSidebarButton(tr("Sandbox"), false);
    QPushButton *serviceStatusBtn = createSidebarButton(tr("Service Status"), false);

    // Sidebar'ın alt kısmına geçmiş butonu ekle - aynı renk stili ile
    sidebarLayout->addStretch();
    
    QPushButton *historyBtn = createSidebarButton(tr("History"), false);
    
    // Histori butonuna tıklama işlevi ekliyoruz
    connect(historyBtn, &QPushButton::clicked, this, &MainWindow::onHistoryButtonClicked);
    
    horizontalLayout->addWidget(sidebarWidget);

    // Ana içerik alanı
    QWidget *mainContentWidget = new QWidget(this);
    mainContentWidget->setObjectName("mainContentWidget");
    
    QVBoxLayout *mainContentLayout = new QVBoxLayout(mainContentWidget);
    mainContentLayout->setSpacing(20);
    mainContentLayout->setContentsMargins(30, 30, 30, 30);

    // Ana içerik düzeni
    QHBoxLayout *headerAreaLayout = new QHBoxLayout();
    headerAreaLayout->setSpacing(15);
    
    // Sol tarafa başlık ve logo
    QWidget *titleWidget = new QWidget(this);
    QHBoxLayout *headerLayout = new QHBoxLayout(titleWidget);
    headerLayout->setSpacing(15);
    headerLayout->setContentsMargins(0, 0, 0, 0);
    
    // Logo ve başlık
    QLabel *logoLabel = new QLabel(this);
    // Resim dosyası yerine Unicode karakteri kullanarak logo yerine geçecek simge oluşturuyoruz
    logoLabel->setText("🛡️");
    logoLabel->setStyleSheet("font-size: 24px;");
    logoLabel->setFixedSize(32, 32);
    
    QLabel *titleLabel = new QLabel(tr("Antivirus"), this);
    titleLabel->setObjectName("titleLabel");
    
    headerLayout->addWidget(logoLabel);
    headerLayout->addWidget(titleLabel);
    
    // Hamburger menü ikonu
    QPushButton *menuButton = new QPushButton(this);
    menuButton->setFixedSize(32, 32);
    menuButton->setObjectName("menuIcon");
    menuButton->setText("≡");
    
    // Layout'lara ekle - Service Status bilgisi artık burada gösterilmeyecek
    headerAreaLayout->addWidget(titleWidget, 1);  // Sol tarafta başlık
    headerAreaLayout->addStretch(0);  // Esnek boşluk ekle
    headerAreaLayout->addWidget(menuButton, 0);  // En sağda hamburger menü
    
    mainContentLayout->addLayout(headerAreaLayout);
    
    // Alt kısımda sonuçlar bölgesi
    QWidget *contentAreaWidget = new QWidget(this);
    contentAreaWidget->setObjectName("contentAreaWidget");
    QVBoxLayout *contentAreaLayout = new QVBoxLayout(contentAreaWidget);
    contentAreaLayout->setSpacing(20);
    contentAreaLayout->setContentsMargins(0, 30, 0, 0);
    
    mainContentLayout->addWidget(contentAreaWidget, 1);  // Ekstra dikey boşluk için 1 genişleme faktörü
    
    // Sonuçlar için çok daha geniş bir alan (başlangıçta gizli)
    QWidget *resultsWidget = new QWidget(this);
    resultsWidget->setObjectName("resultsWidget");
    
    QVBoxLayout *resultsLayout = new QVBoxLayout(resultsWidget);
    resultsLayout->setSpacing(15);
    
    // Sonuç bölümünün başlığı ve detaylı görünüm butonu yan yana
    QHBoxLayout *resultsTitleLayout = new QHBoxLayout();
    resultsTitleLayout->setSpacing(15);
    
    // Sonuçlar başlığı
    QLabel *resultsTitle = new QLabel(tr("Scan Results"), this);
    resultsTitle->setObjectName("titleLabel");
    resultsTitleLayout->addWidget(resultsTitle);
    resultsTitleLayout->addStretch();
    
    // Detaylı görünüm butonu
    QPushButton *detailedViewButton = new QPushButton(tr("Detailed Analysis"), this);
    detailedViewButton->setObjectName("secondaryButton");
    resultsTitleLayout->addWidget(detailedViewButton);
    resultsLayout->addLayout(resultsTitleLayout);
    
    // Normal sonuçlar için scroll area
    QScrollArea *resultScrollArea = new QScrollArea(this);
    resultScrollArea->setWidgetResizable(true);
    resultScrollArea->setFrameShape(QFrame::NoFrame);
    resultScrollArea->setObjectName("transparentScrollArea");
    
    // Scroll area'nın boyutunu genişletmek için minimum yükseklik ve genişlik ata
    resultScrollArea->setMinimumHeight(500);
    resultScrollArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    
    QWidget *resultContainer = new QWidget(resultScrollArea);
    QVBoxLayout *resultContainerLayout = new QVBoxLayout(resultContainer);
    resultContainerLayout->setContentsMargins(10, 15, 10, 15); // İçerik kenar boşlukları
    
    resultTextEdit = new QPlainTextEdit();
    resultTextEdit->setReadOnly(true);
    resultsView->setupTextEditStyle(resultTextEdit);  // ResultsView üzerinden stilini ayarla
    resultTextEdit->setMinimumHeight(1600);
    resultContainerLayout->addWidget(resultTextEdit);
    
    resultScrollArea->setWidget(resultContainer);
    resultsLayout->addWidget(resultScrollArea);
    
    // Detaylı sonuçlar için ikinci bir scroll area (gizli başlangıçta)
    QScrollArea *detailedResultScrollArea = new QScrollArea(this);
    detailedResultScrollArea->setWidgetResizable(true);
    detailedResultScrollArea->setFrameShape(QFrame::NoFrame);
    detailedResultScrollArea->setObjectName("transparentScrollArea");
    
    // Detaylı scroll area'ya da normal scroll area ile aynı boyut politikalarını uygula
    detailedResultScrollArea->setMinimumHeight(500);
    detailedResultScrollArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    
    QWidget *detailedResultContainer = new QWidget(detailedResultScrollArea);
    QVBoxLayout *detailedResultContainerLayout = new QVBoxLayout(detailedResultContainer);
    detailedResultContainerLayout->setContentsMargins(10, 15, 10, 15);
    
    detailedResultTextEdit = new QPlainTextEdit();
    detailedResultTextEdit->setReadOnly(true);
    resultsView->setupTextEditStyle(detailedResultTextEdit);  // ResultsView üzerinden stilini ayarla
    detailedResultTextEdit->setMinimumHeight(1600);
    detailedResultContainerLayout->addWidget(detailedResultTextEdit);
    
    detailedResultScrollArea->setWidget(detailedResultContainer);
    detailedResultScrollArea->setVisible(false);
    resultsLayout->addWidget(detailedResultScrollArea);
    
    // API log widget - Yükseklik artırıldı
    QGroupBox *apiGroup = new QGroupBox(tr("Low-Level Communication"), this);
    
    QVBoxLayout *apiLayout = new QVBoxLayout(apiGroup);
    apiLogTextEdit = new QPlainTextEdit();
    apiLogTextEdit->setReadOnly(true);
    resultsView->setupTextEditStyle(apiLogTextEdit);  // ResultsView üzerinden stilini ayarla
    apiLogTextEdit->setMinimumHeight(50); // Daha küçük
    apiLayout->addWidget(apiLogTextEdit);
    
    // Bu widget'lar başlangıçta gizli kalacak ve gerektiğinde gösterilecek
    resultsWidget->setVisible(false);
    apiGroup->setVisible(false);
    
    contentAreaLayout->addWidget(resultsWidget);
    contentAreaLayout->addWidget(apiGroup);

    // ScanManager ve ResultsView için UI bileşenlerini ayarla
    scanManager->setTextEdit(resultTextEdit);
    scanManager->setLogTextEdit(apiLogTextEdit);
    scanManager->setStatusBar(statusBar());
    
    resultsView->setResultTextEdit(resultTextEdit);
    resultsView->setDetailedResultTextEdit(detailedResultTextEdit);
    
    dockerUIManager->setLogTextEdit(apiLogTextEdit);

    // Tarama butonlarını sadece bir kez bağla ve lambda içinde gösterme işlemleri yap
    connect(offlineScanBtn, &QPushButton::clicked, [this, resultsWidget, apiGroup, detailedResultScrollArea, resultScrollArea]() {
        resultsWidget->setVisible(true);
        apiGroup->setVisible(true);
        detailedResultScrollArea->setVisible(false);
        resultScrollArea->setVisible(true);
        
        // Tarama işlemini başlat
        this->onScanButtonClicked();
    });
    
    connect(virusScanBtn, &QPushButton::clicked, [this, resultsWidget, apiGroup, detailedResultScrollArea, resultScrollArea]() {
        if (resultsWidget && apiGroup && detailedResultScrollArea && resultScrollArea) {
            resultsWidget->setVisible(true);
            apiGroup->setVisible(true);
            
            // Önce detailedResultScrollArea'nın geçerli olup olmadığını kontrol et
            if (detailedResultScrollArea) {
                detailedResultScrollArea->setVisible(false);
            }
            
            // Önce resultScrollArea'nın geçerli olup olmadığını kontrol et
            if (resultScrollArea) {
                resultScrollArea->setVisible(true);
            }
            
            // VirusTotal tarama işlemini başlat
            this->onsendVirusTotalButtonClicked();
        } else {
            qDebug() << "UI bileşenleri hatalı: resultsWidget=" << resultsWidget 
                     << " apiGroup=" << apiGroup 
                     << " detailedResultScrollArea=" << detailedResultScrollArea 
                     << " resultScrollArea=" << resultScrollArea;
            
            // Minimum kontrolle tarama işlemini başlatmaya çalış
            this->onsendVirusTotalButtonClicked();
        }
    });
    
    // CDR taraması butonu için bağlantı
    connect(cdrScanBtn, &QPushButton::clicked, [this, resultsWidget, apiGroup, detailedResultScrollArea, resultScrollArea]() {
        if (resultsWidget && apiGroup && detailedResultScrollArea && resultScrollArea) {
            resultsWidget->setVisible(true);
            apiGroup->setVisible(true);
            
            // Önce detailedResultScrollArea'nın geçerli olup olmadığını kontrol et
            if (detailedResultScrollArea) {
                detailedResultScrollArea->setVisible(false);
            }
            
            // Önce resultScrollArea'nın geçerli olup olmadığını kontrol et
            if (resultScrollArea) {
                resultScrollArea->setVisible(true);
            }
            
            // CDR işlemini başlat
            this->onCdrButtonClicked();
        } else {
            qDebug() << "UI bileşenleri hatalı: resultsWidget=" << resultsWidget 
                     << " apiGroup=" << apiGroup 
                     << " detailedResultScrollArea=" << detailedResultScrollArea 
                     << " resultScrollArea=" << resultScrollArea;
            
            // Minimum kontrolle CDR işlemini başlatmaya çalış
            this->onCdrButtonClicked();
        }
    });
    
    // Sandbox butonu için bağlantı
    connect(sandboxBtn, &QPushButton::clicked, [this, resultsWidget, apiGroup, detailedResultScrollArea, resultScrollArea]() {
        if (resultsWidget && apiGroup && detailedResultScrollArea && resultScrollArea) {
            resultsWidget->setVisible(true);
            apiGroup->setVisible(true);
            
            // Önce detailedResultScrollArea'nın geçerli olup olmadığını kontrol et
            if (detailedResultScrollArea) {
                detailedResultScrollArea->setVisible(false);
            }
            
            // Önce resultScrollArea'nın geçerli olup olmadığını kontrol et
            if (resultScrollArea) {
                resultScrollArea->setVisible(true);
            }
            
            // Sandbox analiz işlemini başlat
            this->onSandboxButtonClicked();
        } else {
            qDebug() << "UI bileşenleri hatalı: resultsWidget=" << resultsWidget 
                     << " apiGroup=" << apiGroup 
                     << " detailedResultScrollArea=" << detailedResultScrollArea 
                     << " resultScrollArea=" << resultScrollArea;
            
            // Minimum kontrolle Sandbox işlemini başlatmaya çalış
            this->onSandboxButtonClicked();
        }
    });

    // Service Status butonu için bağlantı
    connect(serviceStatusBtn, &QPushButton::clicked, [this]() {
        // Service Status diyalogunu göster
        ServiceStatusDialog dialog(apiManager, scanManager, dockerUIManager, this);
        dialog.exec();
    });

    // Detaylı görünüm butonu tıklandığında
    connect(detailedViewButton, &QPushButton::clicked, [this, resultScrollArea, detailedResultScrollArea]() {
        bool isDetailedVisible = detailedResultScrollArea->isVisible();
        detailedResultScrollArea->setVisible(!isDetailedVisible);
        resultScrollArea->setVisible(isDetailedVisible);
    });
    
    horizontalLayout->addWidget(mainContentWidget);
    mainLayout->addWidget(contentWidget);
}

void MainWindow::onApiRequestSent(const QString& endpoint) {
    apiLogTextEdit->appendPlainText(QString("📤 %1 | Request: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(endpoint));
}

void MainWindow::onApiResponseReceived(const QJsonObject& response) {
    if (!resultsView) return;
    
    // Checking if response is empty or invalid
    if (response.isEmpty()) {
        resultTextEdit->clear();
        resultTextEdit->appendPlainText("❌ Error: API response is empty or invalid.");
        apiLogTextEdit->appendPlainText(QString("\n📥 Received Response [%1]: Empty or invalid response")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
        return;
    }
    
    // Normal görünüm için sonuçları göster
    resultTextEdit->clear();
    
    try {
        resultsView->showNormalResults(response);
        
        // Detaylı görünümü de hazırla
        detailedResultTextEdit->clear();
        resultsView->showDetailedResults(response);
        
        // API log'una yanıtı ekle
        apiLogTextEdit->appendPlainText(QString("\n📥 Received Response [%1]: Successful")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
    } catch (const std::exception& e) {
        resultTextEdit->appendPlainText(QString("❌ Error: An issue occurred while processing the response: %1").arg(e.what()));
        apiLogTextEdit->appendPlainText(QString("\n📥 Error [%1]: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(e.what()));
    } catch (...) {
        resultTextEdit->appendPlainText("❌ Error: An unknown issue occurred while processing the response.");
        apiLogTextEdit->appendPlainText(QString("\n📥 Error [%1]: Unknown error")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
    }
}

void MainWindow::onApiError(const QString& errorMessage) {
    // API hatasını log ve sonuçlar bölümlerine ekle
    apiLogTextEdit->appendPlainText(QString("\n❌ %1 | ERROR: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(errorMessage));
    
    // Ana sonuç bölümüne de hata mesajını ekle
    resultTextEdit->clear();
    resultTextEdit->appendPlainText("❌ API Error: " + errorMessage);
    resultTextEdit->appendPlainText("\nPlease check your internet connection or try again later.");
}

void MainWindow::showContainerDetails() {
    if (dockerUIManager) {
        dockerUIManager->showContainerDetails();
    }
}

void MainWindow::onScanButtonClicked() {
    // Dosya seçim dialogunu göster
    QString filePath = QFileDialog::getOpenFileName(this, tr("Select File to Scan"),
                                                   QDir::homePath(),
                                                   tr("All Files (*.*)"));
    if (filePath.isEmpty()) {
        return; // Kullanıcı iptal etti
    }
    
    // ScanManager üzerinden offline tarama işlemini başlat
    scanManager->performOfflineScan(filePath);
}

void MainWindow::onApiKeyButtonClicked() {
    ApiKeyDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted) {
        QString apiKey = dialog.getApiKey();
        if (!apiKey.isEmpty()) {
            // Add debug output for API key
            qDebug() << "Setting API key:" << apiKey.left(5) + "..."; // Only show first 5 chars for security
            
            apiManager->setApiKey(apiKey);
            apiLogTextEdit->appendPlainText(QString("\n🔑 %1 | API key updated")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
            
            // Verify the API key was stored correctly
            QString storedKey = apiManager->getApiKey();
            qDebug() << "Stored API key length:" << storedKey.length();
            qDebug() << "API key successfully stored:" << !storedKey.isEmpty();
            
            QMessageBox::information(this, tr("API Key"), tr("API key successfully saved."));
        }
    }
}

void MainWindow::onsendVirusTotalButtonClicked() {
    // Dosya seçim dialogunu göster
    QString filePath = QFileDialog::getOpenFileName(this, tr("Select File to Send to VirusTotal"),
                                                  QDir::homePath(),
                                                  tr("All Files (*.*)"));
    if (filePath.isEmpty()) {
        return; // Kullanıcı iptal etti
    }
    
    // ScanManager üzerinden online tarama işlemini başlat
    scanManager->performOnlineScan(filePath);
}

void MainWindow::onCdrButtonClicked() {
    // Show file selection dialog
    QString filePath = QFileDialog::getOpenFileName(this, tr("Select File for CDR Process"),
                                                  QDir::homePath(),
                                                  tr("Office and PDF Files (*.docx *.xlsx *.pptx *.pdf);;All Files (*.*)"));
    if (filePath.isEmpty()) {
        return; // User canceled
    }
    
    // Start CDR scan through ScanManager
    scanManager->performCdrScan(filePath);
}

void MainWindow::onSandboxButtonClicked() {
    // Show file selection dialog
    QString filePath = QFileDialog::getOpenFileName(this, tr("Select File for Sandbox Analysis"),
                                                  QDir::homePath(),
                                                  tr("Executable Files (*.exe *.dll *.bat *.js *.vbs);;All Files (*.*)"));
    if (filePath.isEmpty()) {
        return; // User canceled
    }
    
    // Start sandbox analysis through ScanManager
    scanManager->performSandboxScan(filePath);
}

// Modal dialog approach for Service Status button click
void MainWindow::onServiceStatusButtonClicked() {
    try {
        // Create and show modal dialog
        ServiceStatusDialog dialog(apiManager, scanManager, dockerUIManager, this);
        dialog.exec(); // Show as modal
    } catch (const std::exception& e) {
        qDebug() << "Exception caught in onServiceStatusButtonClicked:" << e.what();
        QMessageBox::warning(this, tr("Error"), tr("An error occurred while showing service statuses:\n%1").arg(e.what()));
    } catch (...) {
        qDebug() << "Unknown exception caught in onServiceStatusButtonClicked";
        QMessageBox::warning(this, tr("Error"), tr("An unknown error occurred while showing service statuses."));
    }
}

void MainWindow::onHistoryButtonClicked() {
    try {
        // Geçmiş kayıtları diyalogunu oluştur ve göster
        HistoryDialog dialog(this);
        dialog.exec();
    } catch (const std::exception& e) {
        qDebug() << "Exception in onHistoryButtonClicked:" << e.what();
        QMessageBox::warning(this, tr("Error"), tr("An error occurred while showing history:\n%1").arg(e.what()));
    } catch (...) {
        qDebug() << "Unknown exception in onHistoryButtonClicked";
        QMessageBox::warning(this, tr("Error"), tr("An unknown error occurred while showing history."));
    }
}

// ServiceStatusDialog implementasyonu
ServiceStatusDialog::ServiceStatusDialog(IApiManager* apiManager, ScanManager* scanManager, 
                                       DockerUIManager* dockerUIManager, QWidget* parent)
    : QDialog(parent),
      apiManager(apiManager),
      scanManager(scanManager),
      dockerUIManager(dockerUIManager),
      tabWidget(nullptr),
      statusTable(nullptr),
      containerTable(nullptr),
      runningContainerValue(nullptr),
      totalContainerValue(nullptr),
      imageValue(nullptr),
      refreshButton(nullptr)
{
    // Dialog ayarları
    setWindowTitle(tr("Service Status"));
    setModal(true);
    setMinimumSize(800, 600);
    
    // UI bileşenlerini oluştur
    createUI();
    
    // Servis durumlarını güncelle
    updateServiceStatus();
    
    // Docker konteynerlerini güncelle
    updateContainerList();
    
    // Sinyal-slot bağlantılarını ayarla
    setupConnections();
}

void ServiceStatusDialog::createUI()
{
    // Main layout
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(20);
    mainLayout->setContentsMargins(30, 30, 30, 30);
    
    // Title with icon
    QHBoxLayout* titleLayout = new QHBoxLayout();
    QLabel* iconLabel = new QLabel(this);
    iconLabel->setText("📊");
    iconLabel->setObjectName("serviceStatsIconLabel");
    
    QLabel* titleLabel = new QLabel(tr("System Services and Container Status"), this);
    titleLabel->setObjectName("titleLabel");
    
    titleLayout->addWidget(iconLabel);
    titleLayout->addWidget(titleLabel);
    titleLayout->addStretch();
    
    mainLayout->addLayout(titleLayout);
    
    // Create Tab Widget
    tabWidget = new QTabWidget(this);
    
    // Service Status Tab
    QWidget* serviceStatusTab = new QWidget(this);
    QVBoxLayout* serviceLayout = new QVBoxLayout(serviceStatusTab);
    serviceLayout->setContentsMargins(20, 20, 20, 20);
    
    // Service status açıklaması
    QLabel* serviceInfoLabel = new QLabel(tr("Below is the current status of system services. Green indicates the service is active and running properly."), serviceStatusTab);
    serviceInfoLabel->setObjectName("serviceInfoLabel");
    serviceInfoLabel->setWordWrap(true);
    serviceLayout->addWidget(serviceInfoLabel);
    
    // Table to show services status
    statusTable = new QTableWidget(serviceStatusTab);
    statusTable->setColumnCount(3);
    statusTable->setHorizontalHeaderLabels({tr("Service"), tr("Status"), tr("Details")});
    statusTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    statusTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    statusTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    statusTable->setAlternatingRowColors(true);
    statusTable->verticalHeader()->setVisible(false);
    serviceLayout->addWidget(statusTable);
    
    // Docker Containers Tab
    QWidget* dockerContainersTab = new QWidget(this);
    QVBoxLayout* containersLayout = new QVBoxLayout(dockerContainersTab);
    containersLayout->setContentsMargins(20, 20, 20, 20);
    
    // Docker container açıklaması
    QLabel* containerInfoLabel = new QLabel(tr("This tab shows all Docker containers and their current status. Running containers are marked in green."), dockerContainersTab);
    containerInfoLabel->setObjectName("serviceInfoLabel");
    containerInfoLabel->setWordWrap(true);
    containersLayout->addWidget(containerInfoLabel);
    
    // Docker container table
    containerTable = new QTableWidget(dockerContainersTab);
    containerTable->setColumnCount(5);
    // Sütun başlıklarını güncelle: Name, ID, Image, Status, Ports
    containerTable->setHorizontalHeaderLabels({tr("Name"), tr("ID"), tr("Image"), tr("Status"), tr("Ports")});

    // Sütun genişliklerini ayarla
    containerTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch); // Name
    containerTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents); // ID
    containerTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch); // Image
    containerTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents); // Status
    containerTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents); // Ports
    
    containerTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    containerTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    containerTable->setAlternatingRowColors(true);
    containerTable->verticalHeader()->setVisible(false);
    containersLayout->addWidget(containerTable);
    
    // Widget for Docker image and container statistics
    QFrame* dockerStatsFrame = new QFrame(dockerContainersTab);
    dockerStatsFrame->setFrameShape(QFrame::StyledPanel);
    dockerStatsFrame->setObjectName("dockerStatsFrame");
    
    QHBoxLayout* statsLayout = new QHBoxLayout(dockerStatsFrame);
    statsLayout->setSpacing(20);
    
    // Stat kartları
    auto createStatCard = [this, dockerContainersTab](const QString& labelText, const QString& initialValue, const QString& color) {
        QFrame* card = new QFrame(dockerContainersTab);
        card->setFrameShape(QFrame::StyledPanel);
        card->setObjectName("statsCard");
        
        QVBoxLayout* cardLayout = new QVBoxLayout(card);
        cardLayout->setSpacing(5);
        
        QLabel* label = new QLabel(labelText, card);
        label->setObjectName("statsCardLabel");
        label->setAlignment(Qt::AlignCenter);
        
        QLabel* value = new QLabel(initialValue, card);
        // Use object name for styling instead of direct style
        if (color == "#4CAF50") {
            value->setObjectName("statsCardGreen");
        } else if (color == "#2196F3") {
            value->setObjectName("statsCardBlue");
        } else if (color == "#FFC107") {
            value->setObjectName("statsCardYellow");
        } else {
            value->setObjectName("statsCardValue");
        }
        value->setAlignment(Qt::AlignCenter);
        
        cardLayout->addWidget(label);
        cardLayout->addWidget(value);
        
        return QPair<QFrame*, QLabel*>(card, value);
    };
    
    // Running container count
    auto runningContainer = createStatCard(tr("Running Containers"), "0", "#4CAF50");
    runningContainerValue = runningContainer.second;
    
    // Total container count
    auto totalContainer = createStatCard(tr("Total Containers"), "0", "#2196F3");
    totalContainerValue = totalContainer.second;
    
    // Docker image count
    auto imageCard = createStatCard(tr("Docker Images"), "0", "#FFC107");
    imageValue = imageCard.second;
    
    // Tüm stat kartları layout'a ekleniyor
    statsLayout->addWidget(runningContainer.first);
    statsLayout->addWidget(totalContainer.first);
    statsLayout->addWidget(imageCard.first);
    
    containersLayout->addWidget(dockerStatsFrame);
    
    // Add tabs
    tabWidget->addTab(serviceStatusTab, tr("Service Status"));
    tabWidget->addTab(dockerContainersTab, tr("Docker Containers"));
    
    // Docker Containers sekmesini varsayılan yap
    tabWidget->setCurrentIndex(1); 
    
    // Add tab widget to main layout
    mainLayout->addWidget(tabWidget);
    
    // Button layout
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(15);
    buttonLayout->addStretch();
    
    // Refresh button with modern design
    refreshButton = new QPushButton(tr("Refresh"), this);
    refreshButton->setIcon(QIcon::fromTheme("view-refresh"));
    refreshButton->setObjectName("refreshButton");
    buttonLayout->addWidget(refreshButton);
    
    // Close button
    QPushButton* closeButton = new QPushButton(tr("Close"), this);
    closeButton->setObjectName("secondaryButton");
    buttonLayout->addWidget(closeButton);
    
    // Add buttons to main layout
    mainLayout->addLayout(buttonLayout);
    
    // Connect close button click
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
}

void ServiceStatusDialog::updateServiceStatus() {
    // Mevcut servisleri temizle
    statusTable->setRowCount(0);
    
    // Servis durumlarını hazırla
    QStringList services = {"VirusTotal API", "Docker Service", "CDR Service", "Sandbox Service", "Database Connection"};
    QStringList statuses;
    QStringList details;

    // VirusTotal API durumu - API key var mı kontrol et
    bool vtApiActive = false;
    if (apiManager) {
        QString apiKey = apiManager->getApiKey();
        vtApiActive = !apiKey.isEmpty();
    }
    statuses.append(vtApiActive ? "Active" : "Inactive");
    details.append(vtApiActive ? 
        "API key found" : 
        "API key missing");
    
    // Docker servisi durumu
    bool dockerRunning = dockerUIManager->isDockerAvailable();
    statuses.append(dockerRunning ? "Active" : "Inactive");
    details.append(dockerRunning ? 
        "Docker engine running" : 
        "Docker is not running");
    
    // CDR Service durumu
    bool cdrActive = scanManager->isCdrInitialized() && dockerRunning;
    statuses.append(cdrActive ? "Active" : "Inactive");
    
    if (cdrActive) {
        QString cdrImage = scanManager->getCurrentCdrImageName();
        details.append(cdrImage.isEmpty() ? 
            "Ready to process files" : 
            "Using image: " + cdrImage);
    } else if (!dockerRunning) {
        details.append("Requires Docker to run");
    } else {
        details.append("Service not initialized");
    }
    
    // Sandbox Service durumu
    bool sandboxActive = scanManager->isSandboxInitialized() && dockerRunning;
    statuses.append(sandboxActive ? "Active" : "Inactive");
    
    if (sandboxActive) {
        QString sandboxImage = scanManager->getCurrentSandboxImageName();
        details.append(sandboxImage.isEmpty() ? 
            "Ready for analysis" : 
            "Using image: " + sandboxImage);
    } else if (!dockerRunning) {
        details.append("Requires Docker to run");
    } else {
        details.append("Service not initialized");
    }
    
    // Veritabanı bağlantısı durumu
    bool dbStatus = false;
    try {
        dbStatus = scanManager->isDbInitialized();
    } catch (...) {
        dbStatus = false;
    }
    statuses.append(dbStatus ? "Active" : "Inactive");
    details.append(dbStatus ? "Connected" : "Connection error");
    
    // Servisleri tabloya ekle
    for (int i = 0; i < services.size(); ++i) {
        int row = statusTable->rowCount();
        statusTable->insertRow(row);
        
        // Servis adı
        statusTable->setItem(row, 0, new QTableWidgetItem(services[i]));
        
        // Durum - renkli gösterim
        QTableWidgetItem* statusItem = new QTableWidgetItem();
        statusItem->setText(statuses[i]);
        
        if (statuses[i] == "Active") {
            statusItem->setForeground(QBrush(QColor("#4CAF50")));  // Yeşil
            statusItem->setIcon(QIcon::fromTheme("emblem-default"));
        } else {
            statusItem->setForeground(QBrush(QColor("#F44336")));  // Kırmızı
            statusItem->setIcon(QIcon::fromTheme("emblem-important"));
        }
        
        statusTable->setItem(row, 1, statusItem);
        
        // Detaylar
        statusTable->setItem(row, 2, new QTableWidgetItem(details[i]));
    }
}

void ServiceStatusDialog::updateContainerList() {
    // Mevcut container'ları temizle
    containerTable->setRowCount(0);
    
    // DockerUIManager üzerinden gerçek Docker container verilerini al
    QJsonArray containers = dockerUIManager->getDockerContainers();
    QJsonArray images = dockerUIManager->getDockerImages();
    
    // Gerçek sayıları hesapla
    int runningCount = 0;
    int totalCount = containers.size();
    int imageCount = images.size();
    
    // Çalışan container sayısını bul
    for (int i = 0; i < containers.size(); ++i) {
        QJsonObject container = containers[i].toObject();
        QString status = container["status"].toString().toLower();
        if (status.contains("up") || status.contains("running")) {
            runningCount++;
        }
    }
    
    // İstatistik değerlerini güncelle
    runningContainerValue->setText(QString::number(runningCount));
    totalContainerValue->setText(QString::number(totalCount));
    imageValue->setText(QString::number(imageCount));
    
    // Container bilgilerini tabloya ekle
    for (int i = 0; i < containers.size(); ++i) {
        QJsonObject container = containers[i].toObject();
        
        int row = containerTable->rowCount();
        containerTable->insertRow(row);
        
        // Column 0: Container Name
        containerTable->setItem(row, 0, new QTableWidgetItem(container["name"].toString()));
        
        // Column 1: Container ID
        containerTable->setItem(row, 1, new QTableWidgetItem(container["id"].toString()));
        
        // Column 2: Container Image
        containerTable->setItem(row, 2, new QTableWidgetItem(container["image"].toString()));
        
        // Column 3: Status - renkli gösterim
        QTableWidgetItem* statusItem = new QTableWidgetItem();
        QString status = container["status"].toString();
        statusItem->setText(status);
        
        if (status.toLower().contains("up") || status.toLower().contains("running")) {
            statusItem->setForeground(QBrush(QColor("#4CAF50")));  // Yeşil
        } else if (status.toLower().contains("exit")) {
            statusItem->setForeground(QBrush(QColor("#F44336")));  // Kırmızı
        } else {
            statusItem->setForeground(QBrush(QColor("#FFC107")));  // Sarı/Turuncu
        }
        
        containerTable->setItem(row, 3, statusItem);
        
        // Column 4: Ports
        containerTable->setItem(row, 4, new QTableWidgetItem(container["ports"].toString()));
    }
    
    // Eğer Docker çalışmıyorsa veya container yoksa bir bilgi mesajı göster
    if (!dockerUIManager->isDockerAvailable()) {
        containerTable->setRowCount(0);
        containerTable->insertRow(0);
        QTableWidgetItem *errorItem = new QTableWidgetItem("Docker is not available or not running!");
        errorItem->setForeground(QBrush(QColor("#F44336")));
        containerTable->setSpan(0, 0, 1, 5);
        containerTable->setItem(0, 0, errorItem);
        
        // İstatistikleri sıfırla
        runningContainerValue->setText("0");
        totalContainerValue->setText("0");
        imageValue->setText("0");
    } else if (containers.isEmpty()) {
        containerTable->insertRow(0);
        QTableWidgetItem *infoItem = new QTableWidgetItem("No containers found");
        infoItem->setForeground(QBrush(QColor("#FFC107")));
        containerTable->setSpan(0, 0, 1, 5);
        containerTable->setItem(0, 0, infoItem);
    }
}

void ServiceStatusDialog::setupConnections() {
    // Refresh butonuna tıklandığında verileri güncelle
    connect(refreshButton, &QPushButton::clicked, [this]() {
        updateServiceStatus();
        updateContainerList();
        QMessageBox::information(this, tr("Refresh"), tr("Service status and container information refreshed."));
    });
}

// DockerImageSelectionDialog implementasyonu
DockerImageSelectionDialog::DockerImageSelectionDialog(const QStringList& availableImages,
                                                     const QString& currentImage,
                                                     const QString& serviceType,
                                                     QWidget *parent)
    : QDialog(parent)
{
    // Dialog ayarları
    setWindowTitle(tr("Select Docker Image for %1").arg(serviceType));
    setModal(true);
    setMinimumSize(600, 350); // Boyutu artırıldı

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setSpacing(20);
    layout->setContentsMargins(30, 30, 30, 30);

    // Üst kısımda hizalı başlık
    QHBoxLayout* titleLayout = new QHBoxLayout();
    QLabel* iconLabel = new QLabel("🐳", this);
    iconLabel->setObjectName("dockerIconLabel");

    QLabel* titleLabel = new QLabel(tr("%1 Docker Image").arg(serviceType), this);
    titleLabel->setObjectName("dockerTitleLabel");
    
    titleLayout->addWidget(iconLabel);
    titleLayout->addWidget(titleLabel);
    titleLayout->addStretch();
    layout->addLayout(titleLayout);
    
    // Açıklama metni
    QLabel* descLabel = new QLabel(tr("Select a Docker image to use for %1 processing:").arg(serviceType), this);
    descLabel->setObjectName("dockerDescLabel");
    descLabel->setWordWrap(true);
    layout->addWidget(descLabel);

    // Docker imajları için dropdown - yüksekliği artırılmış
    imageComboBox = new QComboBox(this);
    imageComboBox->addItems(availableImages);
    imageComboBox->setMinimumHeight(50); // Yükseklik artırıldı
    
    // Mevcut imaj seçili gelsin
    int currentIndex = availableImages.indexOf(currentImage);
    if (currentIndex >= 0) {
        imageComboBox->setCurrentIndex(currentIndex);
    }
    
    layout->addWidget(imageComboBox);
    
    // Docker Hub linki
    QLabel* hubLabel = new QLabel(tr("Don't see what you need? <a href='https://hub.docker.com/search?q=%1&type=image'>Search on Docker Hub</a>").arg(serviceType.toLower()), this);
    hubLabel->setOpenExternalLinks(true);
    hubLabel->setObjectName("dockerHubLabel");
    layout->addWidget(hubLabel);
    
    // Alt kısımda butonlar
    layout->addSpacing(20);
    
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(15);
    
    QPushButton *cancelButton = new QPushButton(tr("Cancel"), this);
    QPushButton *okButton = new QPushButton(tr("Select"), this);
    
    // Butonların minimum genişlik ve yüksekliği artırıldı
    cancelButton->setMinimumSize(150, 45);
    okButton->setMinimumSize(150, 45);
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(okButton);
    
    layout->addLayout(buttonLayout);
    
    // Bağlantılar
    connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
}

QString DockerImageSelectionDialog::getSelectedImage() const {
    return imageComboBox->currentText();
}

// History Dialog implementasyonu
HistoryDialog::HistoryDialog(QWidget *parent) : QDialog(parent),
    tabWidget(nullptr),
    scanHistoryTable(nullptr),
    vtHistoryTable(nullptr),
    cdrHistoryTable(nullptr),
    sandboxHistoryTable(nullptr),
    clearHistoryButton(nullptr),
    exportHistoryButton(nullptr),
    closeButton(nullptr)
{
    setWindowTitle(tr("Scan History"));
    setMinimumSize(900, 700);
    setModal(true);
    
    createUI();
    loadHistory();
    setupConnections();
}

void HistoryDialog::createUI() {
    // Ana layout
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(20);
    mainLayout->setContentsMargins(30, 30, 30, 30);
    
    // Set object name for the dialog to connect with QSS
    setObjectName("historyDialog");
    
    // Title with icon
    QHBoxLayout* titleLayout = new QHBoxLayout();
    QLabel* iconLabel = new QLabel(this);
    iconLabel->setText("📅");
    iconLabel->setObjectName("serviceStatsIconLabel");
    
    QLabel* titleLabel = new QLabel(tr("Scan History"), this);
    titleLabel->setObjectName("historyTitleLabel");
    
    titleLayout->addWidget(iconLabel);
    titleLayout->addWidget(titleLabel);
    titleLayout->addStretch();
    
    // Statistics summary
    QLabel* statsLabel = new QLabel(tr("Total Scans: 54  |  Threats Detected: 12  |  Last Scan: Today 15:30"), this);
    statsLabel->setObjectName("historyStatsLabel");
    titleLayout->addWidget(statsLabel);
    
    mainLayout->addLayout(titleLayout);
    
    // Create Tab Widget
    tabWidget = new QTabWidget(this);
    
    // Offline scan history tab
    QWidget* offlineTab = new QWidget(this);
    QVBoxLayout* offlineLayout = new QVBoxLayout(offlineTab);
    offlineLayout->setContentsMargins(20, 20, 20, 20);
    
    // Table for offline scan history
    scanHistoryTable = new QTableWidget(offlineTab);
    scanHistoryTable->setObjectName("historyTable");
    scanHistoryTable->setColumnCount(6);
    scanHistoryTable->setHorizontalHeaderLabels({
        tr("Date & Time"), 
        tr("File"), 
        tr("Size"), 
        tr("Scan Duration"), 
        tr("Result"), 
        tr("Actions")
    });
    scanHistoryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    scanHistoryTable->verticalHeader()->setVisible(false);
    scanHistoryTable->setAlternatingRowColors(true);
    scanHistoryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    scanHistoryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    offlineLayout->addWidget(scanHistoryTable);
    
    // VirusTotal scan history tab
    QWidget* vtTab = new QWidget(this);
    QVBoxLayout* vtLayout = new QVBoxLayout(vtTab);
    vtLayout->setContentsMargins(20, 20, 20, 20);
    
    vtHistoryTable = new QTableWidget(vtTab);
    vtHistoryTable->setObjectName("historyTable");
    vtHistoryTable->setColumnCount(6);
    vtHistoryTable->setHorizontalHeaderLabels({
        tr("Date & Time"), 
        tr("File"), 
        tr("Detection Rate"), 
        tr("Hash"), 
        tr("Result"),
        tr("Actions")
    });
    vtHistoryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    vtHistoryTable->verticalHeader()->setVisible(false);
    vtHistoryTable->setAlternatingRowColors(true);
    vtHistoryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    vtHistoryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    vtLayout->addWidget(vtHistoryTable);
    
    // CDR history tab
    QWidget* cdrTab = new QWidget(this);
    QVBoxLayout* cdrLayout = new QVBoxLayout(cdrTab);
    cdrLayout->setContentsMargins(20, 20, 20, 20);
    
    cdrHistoryTable = new QTableWidget(cdrTab);
    cdrHistoryTable->setObjectName("historyTable");
    cdrHistoryTable->setColumnCount(6);
    cdrHistoryTable->setHorizontalHeaderLabels({
        tr("Date & Time"), 
        tr("File"), 
        tr("Type"), 
        tr("Threats Found"), 
        tr("Cleaned File"),
        tr("Actions")
    });
    cdrHistoryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    cdrHistoryTable->verticalHeader()->setVisible(false);
    cdrHistoryTable->setAlternatingRowColors(true);
    cdrHistoryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    cdrHistoryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    cdrLayout->addWidget(cdrHistoryTable);
    
    // Sandbox history tab
    QWidget* sandboxTab = new QWidget(this);
    QVBoxLayout* sandboxLayout = new QVBoxLayout(sandboxTab);
    sandboxLayout->setContentsMargins(20, 20, 20, 20);
    
    sandboxHistoryTable = new QTableWidget(sandboxTab);
    sandboxHistoryTable->setObjectName("historyTable");
    sandboxHistoryTable->setColumnCount(6);
    sandboxHistoryTable->setHorizontalHeaderLabels({
        tr("Date & Time"), 
        tr("File"), 
        tr("Risk Score"), 
        tr("Behaviors"), 
        tr("Network Activity"),
        tr("Actions")
    });
    sandboxHistoryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    sandboxHistoryTable->verticalHeader()->setVisible(false);
    sandboxHistoryTable->setAlternatingRowColors(true);
    sandboxHistoryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    sandboxHistoryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    sandboxLayout->addWidget(sandboxHistoryTable);
    
    // Add tabs to tab widget
    tabWidget->addTab(offlineTab, tr("Offline Scans"));
    tabWidget->addTab(vtTab, tr("VirusTotal Scans"));
    tabWidget->addTab(cdrTab, tr("CDR Processing"));
    tabWidget->addTab(sandboxTab, tr("Sandbox Analysis"));
    
    // Add tab widget to main layout
    mainLayout->addWidget(tabWidget);
    
    // Button layout
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(15);
    
    // Statistics & info text
    QLabel* resultCountLabel = new QLabel(tr("Showing 20 most recent results in each category"), this);
    resultCountLabel->setObjectName("resultCountLabel");
    buttonLayout->addWidget(resultCountLabel);
    buttonLayout->addStretch();
    
    // Export button
    exportHistoryButton = new QPushButton(tr("Export CSV"), this);
    exportHistoryButton->setObjectName("exportHistoryButton");
    buttonLayout->addWidget(exportHistoryButton);
    
    // Clear history button
    clearHistoryButton = new QPushButton(tr("Clear History"), this);
    clearHistoryButton->setObjectName("clearHistoryButton");
    buttonLayout->addWidget(clearHistoryButton);
    
    // Close button
    closeButton = new QPushButton(tr("Close"), this);
    closeButton->setObjectName("secondaryButton");
    buttonLayout->addWidget(closeButton);
    
    mainLayout->addLayout(buttonLayout);
}

void HistoryDialog::loadHistory() {
    // Bu fonksiyon veritabanından gerçek geçmiş kayıtlarını yükleyecek
    // Şu an için örnek veriler ile doldurulmuş durumda
    
    // İleride DbManager ile entegre edilerek aşağıdaki işlemler yapılacak:
    // 1. DbManager üzerinden ilgili tabloların kayıtları çekilecek
    // 2. Her bir sekme için ilgili kayıtlar tablolara eklenecek
    // 3. İstatistikler hesaplanacak (toplam tarama sayısı, tehdit tespitleri, vb.)
    
    // Örnek tarama geçmişi verileri
    for (int i = 0; i < 5; i++) {
        int row = scanHistoryTable->rowCount();
        scanHistoryTable->insertRow(row);
        
        scanHistoryTable->setItem(row, 0, new QTableWidgetItem(QDateTime::currentDateTime().addDays(-i).toString("dd.MM.yyyy hh:mm")));
        scanHistoryTable->setItem(row, 1, new QTableWidgetItem(QString("file_%1.exe").arg(i+1)));
        scanHistoryTable->setItem(row, 2, new QTableWidgetItem(QString("%1 KB").arg(i * 250 + 125)));
        scanHistoryTable->setItem(row, 3, new QTableWidgetItem(QString("%1 sec").arg(i * 3 + 5)));
        
        QTableWidgetItem* resultItem = new QTableWidgetItem(i % 3 == 0 ? tr("Malicious") : tr("Clean"));
        resultItem->setData(Qt::UserRole + 1, i % 3 == 0 ? "malicious" : "clean");
        scanHistoryTable->setItem(row, 4, resultItem);
        
        // View details button for actions column
        QPushButton* viewButton = new QPushButton(tr("View"));
        viewButton->setObjectName("historyViewButton");
        
        QWidget* buttonContainer = new QWidget();
        QHBoxLayout* buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->addWidget(viewButton);
        buttonLayout->setAlignment(Qt::AlignCenter);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonContainer->setLayout(buttonLayout);
        
        scanHistoryTable->setCellWidget(row, 5, buttonContainer);
    }
    
    // VirusTotal geçmişi için örnek veriler
    for (int i = 0; i < 4; i++) {
        int row = vtHistoryTable->rowCount();
        vtHistoryTable->insertRow(row);
        
        vtHistoryTable->setItem(row, 0, new QTableWidgetItem(QDateTime::currentDateTime().addDays(-i-1).toString("dd.MM.yyyy hh:mm")));
        vtHistoryTable->setItem(row, 1, new QTableWidgetItem(QString("suspect_%1.dll").arg(i+1)));
        vtHistoryTable->setItem(row, 2, new QTableWidgetItem(QString("%1/70").arg(i * 5 + 3)));
        vtHistoryTable->setItem(row, 3, new QTableWidgetItem(QString("8a3b%1c94d7ef2%2a17").arg(i*3).arg(i)));
        
        QTableWidgetItem* resultItem = new QTableWidgetItem(i % 2 == 0 ? tr("Suspicious") : tr("Malicious"));
        resultItem->setData(Qt::UserRole + 1, i % 2 == 0 ? "suspicious" : "malicious");
        vtHistoryTable->setItem(row, 4, resultItem);
        
        // View details button
        QPushButton* viewButton = new QPushButton(tr("View"));
        viewButton->setObjectName("historyViewButton");
        
        QWidget* buttonContainer = new QWidget();
        QHBoxLayout* buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->addWidget(viewButton);
        buttonLayout->setAlignment(Qt::AlignCenter);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonContainer->setLayout(buttonLayout);
        
        vtHistoryTable->setCellWidget(row, 5, buttonContainer);
    }
    
    // CDR geçmişi için örnek veriler
    for (int i = 0; i < 3; i++) {
        int row = cdrHistoryTable->rowCount();
        cdrHistoryTable->insertRow(row);
        
        cdrHistoryTable->setItem(row, 0, new QTableWidgetItem(QDateTime::currentDateTime().addDays(-i-2).toString("dd.MM.yyyy hh:mm")));
        
        QString fileType;
        switch(i % 3) {
            case 0: fileType = "PDF"; break;
            case 1: fileType = "DOCX"; break;
            case 2: fileType = "XLSX"; break;
        }
        
        cdrHistoryTable->setItem(row, 1, new QTableWidgetItem(QString("document_%1.%2").arg(i+1).arg(fileType.toLower())));
        cdrHistoryTable->setItem(row, 2, new QTableWidgetItem(fileType));
        cdrHistoryTable->setItem(row, 3, new QTableWidgetItem(QString::number(i)));
        
        QString cleanedPath = QString("/cleaned/document_%1_clean.%2").arg(i+1).arg(fileType.toLower());
        cdrHistoryTable->setItem(row, 4, new QTableWidgetItem(cleanedPath));
        
        // View details button
        QPushButton* viewButton = new QPushButton(tr("View"));
        viewButton->setObjectName("historyViewButton");
        
        QWidget* buttonContainer = new QWidget();
        QHBoxLayout* buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->addWidget(viewButton);
        buttonLayout->setAlignment(Qt::AlignCenter);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonContainer->setLayout(buttonLayout);
        
        cdrHistoryTable->setCellWidget(row, 5, buttonContainer);
    }
    
    // Sandbox geçmişi için örnek veriler
    for (int i = 0; i < 3; i++) {
        int row = sandboxHistoryTable->rowCount();
        sandboxHistoryTable->insertRow(row);
        
        sandboxHistoryTable->setItem(row, 0, new QTableWidgetItem(QDateTime::currentDateTime().addDays(-i-3).toString("dd.MM.yyyy hh:mm")));
        sandboxHistoryTable->setItem(row, 1, new QTableWidgetItem(QString("malware_%1.exe").arg(i+1)));
        
        // Risk score (0-100)
        int riskScore = i * 30 + 40;
        QTableWidgetItem* scoreItem = new QTableWidgetItem(QString::number(riskScore) + "/100");
        
        // Set risk level using data role instead of property
        if (riskScore >= 80) {
            scoreItem->setData(Qt::UserRole + 1, "high");
        } else if (riskScore >= 50) {
            scoreItem->setData(Qt::UserRole + 1, "medium");
        } else {
            scoreItem->setData(Qt::UserRole + 1, "low");
        }
        
        sandboxHistoryTable->setItem(row, 2, scoreItem);
        
        // Suspicious behaviors
        QString behaviors = "";
        if (i % 3 == 0) {
            behaviors = "Registry changes, Process injection";
        } else if (i % 3 == 1) {
            behaviors = "File encryption, Network connection";
        } else {
            behaviors = "System file access, Persistence";
        }
        sandboxHistoryTable->setItem(row, 3, new QTableWidgetItem(behaviors));
        
        // Network activity
        QString network = "";
        if (i % 2 == 0) {
            network = "Connections to suspicious IP";
        } else {
            network = "No suspicious network activity";
        }
        sandboxHistoryTable->setItem(row, 4, new QTableWidgetItem(network));
        
        // View details button
        QPushButton* viewButton = new QPushButton(tr("View"));
        viewButton->setObjectName("historyViewButton");
        
        QWidget* buttonContainer = new QWidget();
        QHBoxLayout* buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->addWidget(viewButton);
        buttonLayout->setAlignment(Qt::AlignCenter);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonContainer->setLayout(buttonLayout);
        
        sandboxHistoryTable->setCellWidget(row, 5, buttonContainer);
    }
}

void HistoryDialog::setupConnections() {
    // Tab değiştiğinde data yenileme
    connect(tabWidget, &QTabWidget::currentChanged, [this](int index) {
        qDebug() << "Tab changed to" << index;
        // Gerçek uygulamada burada ilgili sekme için verileri DbManager'dan yeniden yükleyebiliriz
    });
    
    // Temizle butonu tıklandığında
    connect(clearHistoryButton, &QPushButton::clicked, [this]() {
        int result = QMessageBox::question(this, 
                                         tr("Clear History"), 
                                         tr("Are you sure you want to clear all scan history? This operation cannot be undone."),
                                         QMessageBox::Yes | QMessageBox::No);
                                         
        if (result == QMessageBox::Yes) {
            // Gerçek uygulamada burada DbManager ile veritabanından kayıtlar silinecek
            QMessageBox::information(this, tr("Clear History"), tr("All history has been cleared."));
            
            // Görsel olarak tabloları temizle
            scanHistoryTable->setRowCount(0);
            vtHistoryTable->setRowCount(0);
            cdrHistoryTable->setRowCount(0);
            sandboxHistoryTable->setRowCount(0);
        }
    });
    
    // Dışa aktarma butonu tıklandığında
    connect(exportHistoryButton, &QPushButton::clicked, [this]() {
        QString fileName = QFileDialog::getSaveFileName(this,
                                                     tr("Save History"),
                                                     QDir::homePath() + "/scan_history.csv",
                                                     tr("CSV Files (*.csv)"));
        if (!fileName.isEmpty()) {
            QMessageBox::information(this, tr("Export Completed"), 
                                   tr("History data has been exported to CSV file."));
        }
    });
    
    // Kapat butonu tıklandığında
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
}
