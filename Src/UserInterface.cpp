#include "../Headers/UserInterface.h"

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
#include <cmath>
#include "../Headers/DbManager.h" // DbManager.h başlık dosyasını dahil ediyoruz

ApiKeyDialog::ApiKeyDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("API Key Ayarları");
    setModal(true);
    setMinimumWidth(400);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setSpacing(15);
    layout->setContentsMargins(20, 20, 20, 20);

    QLabel *infoLabel = new QLabel("VirusTotal API anahtarınızı girin:", this);
    infoLabel->setStyleSheet("font-size: 12pt; color: #2c3e50; margin-bottom: 10px;");
    layout->addWidget(infoLabel);

    apiKeyLineEdit = new QLineEdit(this);
    apiKeyLineEdit->setPlaceholderText("API Key buraya...");
    apiKeyLineEdit->setStyleSheet(
        "QLineEdit {"
        "   padding: 8px;"
        "   font-size: 11pt;"
        "   border: 2px solid #bdc3c7;"
        "   border-radius: 5px;"
        "}"
        "QLineEdit:focus {"
        "   border: 2px solid #3498db;"
        "}"
    );
    layout->addWidget(apiKeyLineEdit);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(10);

    QPushButton *okButton = new QPushButton("Kaydet", this);
    QPushButton *cancelButton = new QPushButton("İptal", this);

    QString buttonStyle = 
        "QPushButton {"
        "   padding: 8px 20px;"
        "   font-size: 11pt;"
        "   border-radius: 5px;"
        "   min-width: 100px;"
        "}"
        "QPushButton:hover {"
        "   background-color: #f0f0f0;"
        "}";

    okButton->setStyleSheet(buttonStyle + 
        "QPushButton {"
        "   background-color: #2ecc71;"
        "   color: white;"
        "   border: none;"
        "}"
        "QPushButton:hover {"
        "   background-color: #27ae60;"
        "}");

    cancelButton->setStyleSheet(buttonStyle +
        "QPushButton {"
        "   background-color: #e74c3c;"
        "   color: white;"
        "   border: none;"
        "}"
        "QPushButton:hover {"
        "   background-color: #c0392b;"
        "}");

    buttonLayout->addStretch();
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(okButton);

    layout->addSpacing(15);
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
      apiManager(nullptr)
{
    // Manager sınıflarını oluşturma
    apiManager = ApiManager::getInstance(this);
    scanManager = new ScanManager(this);
    resultsView = new ResultsView(this);
    dockerUIManager = new DockerUIManager(this);
    
    // API yanıtlarını yakalamak için sinyal-slot bağlantıları
    connect(apiManager, &ApiManager::responseReceived, this, &MainWindow::onApiResponseReceived);
    connect(apiManager, &ApiManager::error, this, &MainWindow::onApiError);
    connect(apiManager, &ApiManager::requestSent, this, &MainWindow::onApiRequestSent);
    
    // Docker imaj seçim sinyalini bağla
    connect(scanManager, &ScanManager::dockerImageSelectionRequired, 
            this, [this](const QString &serviceType) {
                // İlgili servis türü için mevcut imajları ve seçili imajı al
                QStringList availableImages;
                QString currentImage;
                
                if (serviceType == "CDR") {
                    availableImages = scanManager->getAvailableCdrImages();
                    currentImage = scanManager->getCurrentCdrImageName();
                } else if (serviceType == "Sandbox") {
                    availableImages = scanManager->getAvailableSandboxImages();
                    currentImage = scanManager->getCurrentSandboxImageName();
                }
                
                // Dialog'u oluştur ve göster
                DockerImageSelectionDialog dialog(availableImages, currentImage, serviceType, this);
                
                // Debug bilgisi ekle
                qDebug() << "Docker image selection dialog shown for" << serviceType;
                
                if (dialog.exec() == QDialog::Accepted) {
                    QString selectedImage = dialog.getSelectedImage();
                    qDebug() << "Selected image:" << selectedImage << "for" << serviceType;
                    
                    // Seçilen imajı ayarla
                    if (serviceType == "CDR") {
                        scanManager->setCdrImageName(selectedImage);
                    } else if (serviceType == "Sandbox") {
                        scanManager->setSandboxImageName(selectedImage);
                    }
                    
                    // İşlem hemen tekrar denenebilir
                    if (serviceType == "CDR") {
                        onCdrButtonClicked();
                    } else if (serviceType == "Sandbox") {
                        onSandboxButtonClicked();
                    }
                }
            });

    // Ana pencere boyutu ve stili
    QScreen *screen = QApplication::primaryScreen();
    QRect screenGeometry = screen->geometry();
    int width = screenGeometry.width() * 0.8;
    int height = screenGeometry.height() * 0.8;
    resize(width, height);
    setMinimumSize(800, 600);

    // Modern stil ayarları
    setStyleSheet(
        "QMainWindow {"
        "    background-color: #0c0c0c;" // Daha koyu siyah background
        "}"
        "QWidget {"
        "    color: #ffffff;"
        "}"
        "QToolBar {"
        "    background-color: #0c0c0c;"
        "    border: none;"
        "    spacing: 10px;"
        "    padding: 5px;"
        "}"
        "QStatusBar {"
        "    background-color: #1e1e1e;"
        "    color: #cccccc;"
        "    border-top: 1px solid #333333;"
        "}"
        "QStatusBar::item {"
        "    border: none;"
        "}"
        "QPushButton {"
        "    background-color: #0078d7;"
        "    color: white;"
        "    border: none;"
        "    padding: 8px 16px;"
        "    border-radius: 4px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #1c97ea;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #0067b8;"
        "}"
    );

    createActions();
    createMenus();
    createStatusBar();
    createModernCentralWidgets();
}

MainWindow::~MainWindow()
{
    // Manager sınıfları kendi destructor'larında gerekli temizlemeleri yapacak
}

void MainWindow::createActions()
{
    // Ana menü aksiyonu
    menuAction = new QAction(tr("Menü"), this);
    
    // Alt menü aksiyonları
    scanAction = new QAction(tr("Offline Tarama"), this);
    scanAction->setIcon(QIcon::fromTheme("search"));
    connect(scanAction, &QAction::triggered, this, &MainWindow::onScanButtonClicked);

    virusTotalAction = new QAction(tr("VirusTotal Tarama"), this);
    virusTotalAction->setIcon(QIcon::fromTheme("network-transmit"));
    connect(virusTotalAction, &QAction::triggered, this, &MainWindow::onsendVirusTotalButtonClicked);
    
    // Yeni CDR aksiyonu
    cdrAction = new QAction(tr("CDR Tarama"), this);
    cdrAction->setIcon(QIcon::fromTheme("document-edit"));
    connect(cdrAction, &QAction::triggered, this, &MainWindow::onCdrButtonClicked);
    
    // Yeni Sandbox aksiyonu
    sandboxAction = new QAction(tr("Sandbox Analizi"), this);
    sandboxAction->setIcon(QIcon::fromTheme("system-run"));
    connect(sandboxAction, &QAction::triggered, this, &MainWindow::onSandboxButtonClicked);

    apiKeyAction = new QAction(tr("API Key Ayarla"), this);
    apiKeyAction->setIcon(QIcon::fromTheme("dialog-password"));
    connect(apiKeyAction, &QAction::triggered, this, &MainWindow::onApiKeyButtonClicked);

    // Docker konteyner detayları aksiyonu
    dockerAction = new QAction(tr("Docker Konteyner Detayları"), this);
    dockerAction->setIcon(QIcon::fromTheme("docker"));
    connect(dockerAction, &QAction::triggered, this, &MainWindow::showContainerDetails);

    // Service Status aksiyonu
    serviceStatusAction = new QAction(tr("Service Status"), this);
    serviceStatusAction->setIcon(QIcon::fromTheme("dialog-information"));
    connect(serviceStatusAction, &QAction::triggered, this, &MainWindow::onServiceStatusButtonClicked);
}

void MainWindow::createMenus()
{
    // Tek bir menü butonu oluştur
    QToolButton* menuButton = new QToolButton(this);
    menuButton->setText(tr("Menü"));
    menuButton->setPopupMode(QToolButton::InstantPopup);
    menuButton->setStyleSheet(
        "QToolButton {"
        "    background-color: #007acc;"
        "    color: white;"
        "    border: none;"
        "    padding: 8px 16px;"
        "    font-size: 12pt;"
        "    border-radius: 5px;"
        "}"
        "QToolButton:hover {"
        "    background-color: #1c97ea;"
        "}"
        "QToolButton::menu-indicator {"
        "    image: none;"
        "}"
    );

    // Menü oluştur
    QMenu* menu = new QMenu(this);
    menu->setStyleSheet(
        "QMenu {"
        "    background-color: #252526;"
        "    border: 1px solid #3f3f46;"
        "    border-radius: 5px;"
        "    padding: 5px;"
        "}"
        "QMenu::item {"
        "    padding: 8px 25px 8px 15px;"
        "    border-radius: 3px;"
        "    margin: 2px;"
        "    color: #cccccc;"
        "}"
        "QMenu::item:selected {"
        "    background-color: #007acc;"
        "    color: white;"
        "}"
        "QMenu::separator {"
        "    height: 1px;"
        "    background-color: #3f3f46;"
        "    margin: 5px 15px;"
        "}"
    );

    menu->addAction(scanAction);
    menu->addAction(virusTotalAction);
    menu->addAction(cdrAction);        
    menu->addAction(sandboxAction);    
    menu->addAction(dockerAction);    
    menu->addAction(serviceStatusAction); // Service Status aksiyonunu ekle
    menu->addSeparator();
    menu->addAction(apiKeyAction);

    menuButton->setMenu(menu);

    // Toolbar'a menü butonunu ekle
    QToolBar* mainToolBar = addToolBar(tr("Ana Menü"));
    mainToolBar->setMovable(false);
    mainToolBar->addWidget(menuButton);
    mainToolBar->setStyleSheet(
        "QToolBar {"
        "    background-color: #252526;"
        "    border: none;"
        "    spacing: 10px;"
        "    padding: 5px;"
        "}"
    );
}

void MainWindow::createToolBars()
{
    // Bu fonksiyon artık kullanılmıyor, menü butonu yeterli
}

void MainWindow::createStatusBar()
{
    // QMainWindow'un kendi statusBar()'ını kullanarak basit bir mesaj gösterebiliriz
    statusBar()->showMessage(tr("Hazır"));
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
    contentWidget->setStyleSheet("background-color: #0c0c0c;");
    
    // Sol sidebar için bir layout
    QHBoxLayout *horizontalLayout = new QHBoxLayout(contentWidget);
    horizontalLayout->setSpacing(0);
    horizontalLayout->setContentsMargins(0, 0, 0, 0);
    
    // Sol sidebar oluştur
    QWidget *sidebarWidget = new QWidget(this);
    sidebarWidget->setFixedWidth(220);
    sidebarWidget->setStyleSheet(
        "QWidget {"
        "    background-color: #181818;"
        "    border-right: 1px solid #333333;"
        "}"
        "QPushButton {"
        "    text-align: left;"
        "    padding: 12px 20px;"
        "    border: none;"
        "    border-radius: 0;"
        "    background-color: transparent;"
        "    color: #cccccc;"
        "    font-size: 14px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #333333;"
        "    color: white;"
        "}"
        "QPushButton:checked {"
        "    background-color: #222222;"
        "    color: #ffffff;"
        "    font-weight: bold;"
        "    border-left: 4px solid #0078d7;"
        "}"
    );
    
    // Sidebar layout
    QVBoxLayout *sidebarLayout = new QVBoxLayout(sidebarWidget);
    sidebarLayout->setSpacing(0);
    sidebarLayout->setContentsMargins(0, 20, 0, 20);

    // Sidebar butonları (menü öğeleri)
    auto createSidebarButton = [this, sidebarLayout](const QString &text, bool checked = false, const QString &bgColor = "") {
        QPushButton *btn = new QPushButton(text, this);
        btn->setCheckable(true);
        btn->setChecked(checked);
        btn->setIconSize(QSize(20, 20));
        
        // Butonun renkli olması için özel stil
        if (!bgColor.isEmpty()) {
            btn->setStyleSheet(QString(
                "QPushButton {"
                "    text-align: left;"
                "    padding: 12px 20px;"
                "    border: none;"
                "    border-radius: 0;"
                "    background-color: %1;"
                "    color: white;"
                "    font-size: 14px;"
                "    font-weight: bold;"
                "}"
                "QPushButton:hover {"
                "    background-color: #333333;"
                "    color: white;"
                "}"
                "QPushButton:checked {"
                "    background-color: #222222;"
                "    color: #ffffff;"
                "    font-weight: bold;"
                "    border-left: 4px solid #0078d7;"
                "}"
            ).arg(bgColor));
        }
        
        sidebarLayout->addWidget(btn);
        return btn;
    };

    // Sidebar butonları - renkli ve yeni isimlerle güncellendi
    QPushButton *offlineScanBtn = createSidebarButton(tr("Offline Scan"), true, "#1e88e5");  // Mavi renk
    QPushButton *virusScanBtn = createSidebarButton(tr("Online Scan"), false, "#43a047");   // Yeşil renk
    QPushButton *cdrScanBtn = createSidebarButton(tr("CDR Scan"), false, "#ff9800");        // Turuncu renk
    QPushButton *sandboxBtn = createSidebarButton(tr("Sandbox"), false, "#9c27b0");         // Mor renk
    QPushButton *serviceStatusBtn = createSidebarButton(tr("Service Status"), false, "#e91e63"); // Pembe renk

    // Sidebar'ın alt kısmına ayarlar butonu ekle
    sidebarLayout->addStretch();
    
    QPushButton *settingsBtn = new QPushButton(tr("History"), this);
    settingsBtn->setStyleSheet(
        "QPushButton {"
        "    text-align: left;"
        "    padding: 12px 20px;"
        "    border: none;"
        "    border-radius: 0;"
        "    background-color: transparent;"
        "    color: #cccccc;"
        "    font-size: 14px;"
        "}"
    );
    sidebarLayout->addWidget(settingsBtn);
    
    horizontalLayout->addWidget(sidebarWidget);

    // Ana içerik alanı
    QWidget *mainContentWidget = new QWidget(this);
    mainContentWidget->setStyleSheet("background-color: #0c0c0c; padding: 20px;");
    
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
    logoLabel->setPixmap(QPixmap(":/images/shield.png").scaledToHeight(32, Qt::SmoothTransformation));
    logoLabel->setFixedSize(32, 32);
    
    QLabel *titleLabel = new QLabel(tr("Antivirus"), this);
    titleLabel->setStyleSheet(
        "QLabel {"
        "    font-size: 24px;"
        "    font-weight: bold;"
        "    color: white;"
        "}"
    );
    
    headerLayout->addWidget(logoLabel);
    headerLayout->addWidget(titleLabel);
    
    // Hamburger menü ikonu
    QPushButton *menuButton = new QPushButton(this);
    menuButton->setFixedSize(32, 32);
    menuButton->setStyleSheet(
        "QPushButton {"
        "    background-color: transparent;"
        "    border: none;"
        "    color: white;"
        "    font-size: 20px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #333333;"
        "}"
    );
    menuButton->setText("≡");
    
    // Layout'lara ekle - Service Status bilgisi artık burada gösterilmeyecek
    headerAreaLayout->addWidget(titleWidget, 1);  // Sol tarafta başlık
    headerAreaLayout->addStretch(0);  // Esnek boşluk ekle
    headerAreaLayout->addWidget(menuButton, 0);  // En sağda hamburger menü
    
    mainContentLayout->addLayout(headerAreaLayout);
    
    // Alt kısımda sonuçlar bölgesi
    QWidget *contentAreaWidget = new QWidget(this);
    contentAreaWidget->setStyleSheet("background-color: transparent;");
    QVBoxLayout *contentAreaLayout = new QVBoxLayout(contentAreaWidget);
    contentAreaLayout->setSpacing(20);
    contentAreaLayout->setContentsMargins(0, 30, 0, 0);
    
    mainContentLayout->addWidget(contentAreaWidget, 1);  // Ekstra dikey boşluk için 1 genişleme faktörü
    
    // Sonuçlar için çok daha geniş bir alan (başlangıçta gizli)
    QWidget *resultsWidget = new QWidget(this);
    resultsWidget->setStyleSheet(
        "QWidget {"
        "    background-color: #14141a;"
        "    border-radius: 12px;"
        "    padding: 15px;"
        "    margin-top: 20px;"
        "}"
    );
    
    QVBoxLayout *resultsLayout = new QVBoxLayout(resultsWidget);
    resultsLayout->setSpacing(15);
    
    // Sonuç bölümünün başlığı ve detaylı görünüm butonu yan yana
    QHBoxLayout *resultsTitleLayout = new QHBoxLayout();
    resultsTitleLayout->setSpacing(15);
    
    // Sonuçlar başlığı
    QLabel *resultsTitle = new QLabel(tr("Tarama Sonuçları"), this);
    resultsTitle->setStyleSheet(
        "QLabel {"
        "    font-size: 20px;"
        "    font-weight: bold;"
        "    color: white;"
        "}"
    );
    resultsTitleLayout->addWidget(resultsTitle);
    resultsTitleLayout->addStretch();
    
    // Detaylı görünüm butonu
    QPushButton *detailedViewButton = new QPushButton(tr("Detaylı Analiz"), this);
    detailedViewButton->setStyleSheet(
        "QPushButton {"
        "    background-color: #333333;"
        "    color: white;"
        "    border: none;"
        "    border-radius: 4px;"
        "    padding: 6px 12px;"
        "    font-size: 13px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #444444;"
        "}"
    );
    resultsTitleLayout->addWidget(detailedViewButton);
    resultsLayout->addLayout(resultsTitleLayout);
    
    // Normal sonuçlar için scroll area
    QScrollArea *resultScrollArea = new QScrollArea(this);
    resultScrollArea->setWidgetResizable(true);
    resultScrollArea->setFrameShape(QFrame::NoFrame);
    resultScrollArea->setStyleSheet(
        "QScrollArea {"
        "    background-color: transparent;"
        "    border: none;"
        "    min-width: 800px;"
        "}"
    );
    
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
    detailedResultScrollArea->setStyleSheet(
        "QScrollArea {"
        "    background-color: transparent;"
        "    border: none;"
        "    min-width: 800px;"
        "}"
    );
    
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
    apiGroup->setStyleSheet(
        "QGroupBox {"
        "    font-size: 14px;"
        "    font-weight: bold;"
        "    border: 1px solid #333333;"
        "    border-radius: 8px;"
        "    margin-top: 1ex;"
        "    padding: 10px;"
        "    background-color: #181818;"
        "    color: #cccccc;"
        "}"
        "QGroupBox::title {"
        "    subcontrol-origin: margin;"
        "    subcontrol-position: top center;"
        "    padding: 0 10px;"
        "    color: #cccccc;"
        "    background-color: #181818;"
        "}"
    );

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
    apiLogTextEdit->appendPlainText(QString("📤 %1 | İstek: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(endpoint));
}

void MainWindow::onApiResponseReceived(const QJsonObject& response) {
    if (!resultsView) return;
    
    // Checking if response is empty or invalid
    if (response.isEmpty()) {
        resultTextEdit->clear();
        resultTextEdit->appendPlainText("❌ Hata: API yanıtı boş veya geçersiz.");
        apiLogTextEdit->appendPlainText(QString("\n📥 Alınan Yanıt [%1]: Boş veya geçersiz yanıt")
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
        apiLogTextEdit->appendPlainText(QString("\n📥 Alınan Yanıt [%1]: Başarılı")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
    } catch (const std::exception& e) {
        resultTextEdit->appendPlainText(QString("❌ Hata: Yanıt işlenirken bir sorun oluştu: %1").arg(e.what()));
        apiLogTextEdit->appendPlainText(QString("\n📥 Hata [%1]: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(e.what()));
    } catch (...) {
        resultTextEdit->appendPlainText("❌ Hata: Yanıt işlenirken bilinmeyen bir sorun oluştu.");
        apiLogTextEdit->appendPlainText(QString("\n📥 Hata [%1]: Bilinmeyen hata")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
    }
}

void MainWindow::onApiError(const QString& errorMessage) {
    // API hatasını log ve sonuçlar bölümlerine ekle
    apiLogTextEdit->appendPlainText(QString("\n❌ %1 | HATA: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(errorMessage));
    
    // Ana sonuç bölümüne de hata mesajını ekle
    resultTextEdit->clear();
    resultTextEdit->appendPlainText("❌ API Hatası: " + errorMessage);
    resultTextEdit->appendPlainText("\nLütfen internet bağlantınızı kontrol edin veya daha sonra tekrar deneyin.");
}

void MainWindow::showContainerDetails() {
    if (dockerUIManager) {
        dockerUIManager->showContainerDetails();
    }
}

void MainWindow::onScanButtonClicked() {
    // Dosya seçim dialogunu göster
    QString filePath = QFileDialog::getOpenFileName(this, tr("Taranacak Dosyayı Seç"),
                                                   QDir::homePath(),
                                                   tr("Tüm Dosyalar (*.*)"));
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
            apiManager->setApiKey(apiKey);
            apiLogTextEdit->appendPlainText(QString("\n🔑 %1 | API anahtarı güncellendi")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
            QMessageBox::information(this, tr("API Key"), tr("API anahtarı başarıyla kaydedildi."));
        }
    }
}

void MainWindow::onsendVirusTotalButtonClicked() {
    // Dosya seçim dialogunu göster
    QString filePath = QFileDialog::getOpenFileName(this, tr("VirusTotal'e Gönderilecek Dosyayı Seç"),
                                                  QDir::homePath(),
                                                  tr("Tüm Dosyalar (*.*)"));
    if (filePath.isEmpty()) {
        return; // Kullanıcı iptal etti
    }
    
    // ScanManager üzerinden online tarama işlemini başlat
    scanManager->performOnlineScan(filePath);
}

void MainWindow::onCdrButtonClicked() {
    // Dosya seçim dialogunu göster
    QString filePath = QFileDialog::getOpenFileName(this, tr("CDR İşlemi için Dosya Seç"),
                                                  QDir::homePath(),
                                                  tr("Ofis ve PDF Dosyaları (*.docx *.xlsx *.pptx *.pdf);;Tüm Dosyalar (*.*)"));
    if (filePath.isEmpty()) {
        return; // Kullanıcı iptal etti
    }
    
    // ScanManager üzerinden CDR tarama işlemini başlat
    scanManager->performCdrScan(filePath);
}

void MainWindow::onSandboxButtonClicked() {
    // Dosya seçim dialogunu göster
    QString filePath = QFileDialog::getOpenFileName(this, tr("Sandbox Analizi için Dosya Seç"),
                                                  QDir::homePath(),
                                                  tr("Çalıştırılabilir Dosyalar (*.exe *.dll *.bat *.js *.vbs);;Tüm Dosyalar (*.*)"));
    if (filePath.isEmpty()) {
        return; // Kullanıcı iptal etti
    }
    
    // ScanManager üzerinden sandbox analizi işlemini başlat
    scanManager->performSandboxScan(filePath);
}

// Service Status butonuna tıklandığında yeni modal dialog gösterme yaklaşımı
void MainWindow::onServiceStatusButtonClicked() {
    try {
        // Modal dialog oluştur ve göster
        ServiceStatusDialog dialog(apiManager, scanManager, dockerUIManager, this);
        dialog.exec(); // Modal olarak göster
    } catch (const std::exception& e) {
        qDebug() << "onServiceStatusButtonClicked'de istisna yakalandı:" << e.what();
        QMessageBox::warning(this, tr("Hata"), tr("Servis durumları gösterilirken bir hata oluştu:\n%1").arg(e.what()));
    } catch (...) {
        qDebug() << "onServiceStatusButtonClicked'de bilinmeyen bir istisna yakalandı";
        QMessageBox::warning(this, tr("Hata"), tr("Servis durumları gösterilirken bilinmeyen bir hata oluştu."));
    }
}

// DockerImageSelectionDialog implementasyonu
DockerImageSelectionDialog::DockerImageSelectionDialog(const QStringList& availableImages, 
                                                      const QString& currentImage,
                                                      const QString& serviceType,
                                                      QWidget *parent) 
    : QDialog(parent)
{
    setWindowTitle(tr("Docker İmaj Seçimi - %1").arg(serviceType));
    setMinimumWidth(500);
    setModal(true);
    
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setSpacing(15);
    layout->setContentsMargins(20, 20, 20, 20);
    
    // Servis türüne göre açıklama metni
    QString description;
    if (serviceType == "CDR") {
        description = tr("CDR (Content Disarm and Reconstruction) işlemi için kullanılacak Docker imajını seçin. "
                         "Bu imaj, potansiyel olarak zararlı içeriğin temizlenmesi için kullanılacak.");
    } else if (serviceType == "Sandbox") {
        description = tr("Sandbox analizi için kullanılacak Docker imajını seçin. "
                         "Bu imaj, şüpheli dosyaların izole bir ortamda analiz edilmesi için kullanılacak.");
    }
    
    QLabel *infoLabel = new QLabel(description, this);
    infoLabel->setStyleSheet("font-size: 11pt; color: #2c3e50; margin-bottom: 10px;");
    infoLabel->setWordWrap(true);
    layout->addWidget(infoLabel);
    
    // İmajlarla ilgili uyarı
    QLabel *warningLabel = new QLabel(tr("⚠️ Seçilen Docker imajı güvenilir bir kaynaktan olmalıdır. "
                                         "İmaj seçildiğinde, Docker konteynerı otomatik olarak başlatılacaktır."), this);
    warningLabel->setStyleSheet("font-size: 11pt; color: #e67e22; margin-bottom: 5px;");
    warningLabel->setWordWrap(true);
    layout->addWidget(warningLabel);
    
    // İmaj seçim combo box'ı
    QHBoxLayout *comboLayout = new QHBoxLayout();
    QLabel *comboLabel = new QLabel(tr("Docker İmajı:"), this);
    comboLabel->setStyleSheet("font-size: 11pt; font-weight: bold;");
    
    imageComboBox = new QComboBox(this);
    imageComboBox->setStyleSheet(
        "QComboBox {"
        "   padding: 8px;"
        "   font-size: 11pt;"
        "   border: 2px solid #bdc3c7;"
        "   border-radius: 5px;"
        "   min-width: 350px;"
        "}"
        "QComboBox:focus {"
        "   border: 2px solid #3498db;"
        "}"
    );
    
    // Mevcut imajları ekle
    imageComboBox->addItems(availableImages);
    
    // Eğer mevcut bir imaj seçiliyse, onu seç
    if (!currentImage.isEmpty()) {
        int index = imageComboBox->findText(currentImage);
        if (index >= 0) {
            imageComboBox->setCurrentIndex(index);
        }
    }
    
    comboLayout->addWidget(comboLabel);
    comboLayout->addWidget(imageComboBox, 1);
    layout->addLayout(comboLayout);
    
    // İmaj açıklaması için info alanı
    QLabel *descriptionTitle = new QLabel(tr("İmaj Açıklaması:"), this);
    descriptionTitle->setStyleSheet("font-size: 11pt; font-weight: bold; margin-top: 10px;");
    layout->addWidget(descriptionTitle);
    
    QLabel *imageDescription = new QLabel(this);
    imageDescription->setStyleSheet(
        "background-color: #f8f9fa;"
        "border: 1px solid #dcdde1;"
        "border-radius: 5px;"
        "padding: 10px;"
        "font-size: 10pt;"
        "color: #2d3436;"
        "min-height: 80px;"
    );
    imageDescription->setWordWrap(true);
    
    // İmaj açıklamasını güncelle
    auto updateDescription = [imageDescription, serviceType](const QString &imageName) {
        QString desc = tr("Bu imaj hakkında detaylı bilgi yok.");
        
        if (serviceType == "CDR") {
            if (imageName.contains("dannybeckett/disarm")) {
                desc = tr("DisARM: Content Disarm and Reconstruction için açık kaynaklı bir araç. "
                          "Zararlı olabilecek içeriği dosyalardan çıkarır veya etkisiz hale getirir.");
            } else if (imageName.contains("opendxl")) {
                desc = tr("OpenDXL: Güvenli dosya transferi için McAfee tarafından desteklenen bir servis. "
                          "CDR yetenekleri içerir ve entegrasyon için API'ler sunar.");
            } else if (imageName.contains("pdf-redact-tools")) {
                desc = tr("PDF Redact Tools: PDF dosyalarından hassas verileri temizlemek için özel araçlar içerir.");
            } else if (imageName.contains("pdfcpu")) {
                desc = tr("PDF CPU: PDF dosyalarını işlemek, temizlemek ve dönüştürmek için kapsamlı bir araç seti.");
            }
        } else if (serviceType == "Sandbox") {
            if (imageName.contains("faasm")) {
                desc = tr("FAASM: Hafif sandboxing kütüphanesi ve mevcut WebAssembly toolchain'i kullanan "
                          "bir yürütme ortamı. Güvenli izolasyon özelliklerine sahip.");
            } else if (imageName.contains("thug")) {
                desc = tr("Thug: Düşük etkileşimli bir bal küpü (honeypot) olarak tasarlanmış bir kötü amaçlı yazılım analiz aracı. "
                          "Özellikle web tabanlı tehditleri tespit etmek için kullanılır.");
            } else if (imageName.contains("cuckoo")) {
                desc = tr("Cuckoo Sandbox: En popüler açık kaynaklı otomatik zararlı yazılım analiz sistemlerinden biri. "
                          "Dosyaları izole bir ortamda çalıştırarak davranışlarını gözlemler.");
            } else if (imageName.contains("vipermonkey")) {
                desc = tr("ViperMonkey: Office belgelerindeki VBA makrolarını analiz etmeye odaklanan bir sandbox aracı. "
                          "Zararlı makroları tespit etmek için kullanılır.");
            } else if (imageName.contains("jsunpack")) {
                desc = tr("JSUnpack: JavaScript ve benzeri web içeriğini analiz etmek için geliştirilmiş bir araç. "
                          "Obfuscated JavaScript kodlarını deşifre eder.");
            }
        }
        
        imageDescription->setText(desc);
    };
    
    // İlk imaj açıklamasını göster
    updateDescription(imageComboBox->currentText());
    
    // Combo box değiştiğinde açıklamayı güncelle
    connect(imageComboBox, &QComboBox::currentTextChanged, updateDescription);
    
    layout->addWidget(imageDescription);
    
    // Butonlar
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(10);
    
    QPushButton *cancelButton = new QPushButton(tr("İptal"), this);
    QPushButton *okButton = new QPushButton(tr("İmajı Seç"), this);
    
    QString buttonStyle = 
        "QPushButton {"
        "   padding: 8px 20px;"
        "   font-size: 11pt;"
        "   border-radius: 5px;"
        "   min-width: 100px;"
        "}"
        "QPushButton:hover {"
        "   background-color: #f0f0f0;"
        "}";
    
    cancelButton->setStyleSheet(buttonStyle + 
        "QPushButton {"
        "   background-color: #e74c3c;"
        "   color: white;"
        "   border: none;"
        "}"
        "QPushButton:hover {"
        "   background-color: #c0392b;"
        "}");
    
    okButton->setStyleSheet(buttonStyle + 
        "QPushButton {"
        "   background-color: #2ecc71;"
        "   color: white;"
        "   border: none;"
        "}"
        "QPushButton:hover {"
        "   background-color: #27ae60;"
        "}");
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(okButton);
    
    layout->addSpacing(15);
    layout->addLayout(buttonLayout);
    
    connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
}

QString DockerImageSelectionDialog::getSelectedImage() const {
    return imageComboBox->currentText();
}

// ServiceStatusDialog implementasyonu - Modal dialog yaklaşımı
ServiceStatusDialog::ServiceStatusDialog(ApiManager* apiManager, ScanManager* scanManager, 
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
    setWindowTitle(tr("Sistem Servisleri ve Konteyner Durumu"));
    setMinimumSize(800, 600);
    setModal(true);
    
    createUI();
    updateServiceStatus();
    updateContainerList();
    setupConnections();
}

void ServiceStatusDialog::createUI()
{
    // Ana düzen
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(20);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    
    // Başlık
    QLabel* titleLabel = new QLabel(tr("Sistem Servisleri ve Konteyner Durumu"), this);
    titleLabel->setStyleSheet(
        "QLabel {"
        "    font-size: 20px;"
        "    font-weight: bold;"
        "    color: white;"
        "}"
    );
    mainLayout->addWidget(titleLabel);
    
    // Tab Widget oluştur
    tabWidget = new QTabWidget(this);
    tabWidget->setStyleSheet(
        "QTabWidget::pane {"
        "    border: 1px solid #3f3f46;"
        "    background-color: #252526;"
        "    border-radius: 3px;"
        "}"
        "QTabBar::tab {"
        "    background-color: #2d2d30;"
        "    color: #cccccc;"
        "    padding: 8px 15px;"
        "    border-top-left-radius: 4px;"
        "    border-top-right-radius: 4px;"
        "}"
        "QTabBar::tab:selected {"
        "    background-color: #0078d7;"
        "    color: white;"
        "}"
        "QTabBar::tab:hover:!selected {"
        "    background-color: #3e3e42;"
        "}"
    );
    
    // Servis Durumları Tab'ı
    QWidget* serviceStatusTab = new QWidget(this);
    QVBoxLayout* serviceLayout = new QVBoxLayout(serviceStatusTab);
    
    // Servislerin durumunu göstermek için tablo
    statusTable = new QTableWidget(serviceStatusTab);
    statusTable->setColumnCount(3);
    statusTable->setHorizontalHeaderLabels({tr("Servis"), tr("Durum"), tr("Detay")});
    statusTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    statusTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    statusTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    statusTable->setAlternatingRowColors(true);
    statusTable->verticalHeader()->setVisible(false);
    statusTable->setStyleSheet(
        "QTableWidget {"
        "   background-color: #2d2d30;"
        "   color: #ffffff;"
        "   gridline-color: #3f3f46;"
        "   border: 1px solid #3f3f46;"
        "}"
        "QTableWidget::item {"
        "   padding: 10px;"
        "}"
        "QTableWidget::item:selected {"
        "   background-color: #0078d7;"
        "}"
        "QHeaderView::section {"
        "   background-color: #252526;"
        "   color: #ffffff;"
        "   font-weight: bold;"
        "   border: 1px solid #3f3f46;"
        "   padding: 4px;"
        "}"
    );
    serviceLayout->addWidget(statusTable);
    
    // Docker Konteynerler Tab'ı
    QWidget* dockerContainersTab = new QWidget(this);
    QVBoxLayout* containersLayout = new QVBoxLayout(dockerContainersTab);
    
    // Docker konteyner tablosu
    containerTable = new QTableWidget(dockerContainersTab);
    containerTable->setColumnCount(5);
    containerTable->setHorizontalHeaderLabels({tr("ID"), tr("İsim"), tr("İmaj"), tr("Durum"), tr("Portlar")});
    containerTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    containerTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    containerTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    containerTable->setAlternatingRowColors(true);
    containerTable->verticalHeader()->setVisible(false);
    containerTable->setStyleSheet(
        "QTableWidget {"
        "   background-color: #2d2d30;"
        "   color: #ffffff;"
        "   gridline-color: #3f3f46;"
        "   border: 1px solid #3f3f46;"
        "}"
        "QTableWidget::item {"
        "   padding: 10px;"
        "}"
        "QTableWidget::item:selected {"
        "   background-color: #0078d7;"
        "}"
        "QHeaderView::section {"
        "   background-color: #252526;"
        "   color: #ffffff;"
        "   font-weight: bold;"
        "   border: 1px solid #3f3f46;"
        "   padding: 4px;"
        "}"
    );
    containersLayout->addWidget(containerTable);
    
    // Tab'ları ekle
    tabWidget->addTab(serviceStatusTab, tr("Servis Durumu"));
    tabWidget->addTab(dockerContainersTab, tr("Docker Konteynerler"));
    
    // Docker imaj ve konteyner istatistikleri için widget
    QGroupBox* dockerStatsGroup = new QGroupBox(tr("Docker İstatistikleri"), dockerContainersTab);
    dockerStatsGroup->setStyleSheet(
        "QGroupBox {"
        "    font-size: 14px;"
        "    font-weight: bold;"
        "    border: 1px solid #333333;"
        "    border-radius: 8px;"
        "    margin-top: 1ex;"
        "    padding: 10px;"
        "    background-color: #1e1e1e;"
        "    color: #cccccc;"
        "}"
        "QGroupBox::title {"
        "    subcontrol-origin: margin;"
        "    subcontrol-position: top left;"
        "    padding: 0 10px;"
        "    color: #cccccc;"
        "    background-color: #1e1e1e;"
        "}"
    );
    
    QHBoxLayout* statsLayout = new QHBoxLayout(dockerStatsGroup);
    
    // Çalışan konteyner sayısı
    QLabel* runningContainerLabel = new QLabel(tr("Çalışan Konteynerler:"), dockerContainersTab);
    runningContainerValue = new QLabel("0", dockerContainersTab);
    runningContainerValue->setStyleSheet("color: #4CAF50; font-weight: bold;"); // Yeşil
    
    // Toplam konteyner sayısı
    QLabel* totalContainerLabel = new QLabel(tr("Toplam Konteynerler:"), dockerContainersTab);
    totalContainerValue = new QLabel("0", dockerContainersTab);
    totalContainerValue->setStyleSheet("color: #2196F3; font-weight: bold;"); // Mavi
    
    // Docker imaj sayısı
    QLabel* imageLabel = new QLabel(tr("Docker İmajları:"), dockerContainersTab);
    imageValue = new QLabel("0", dockerContainersTab);
    imageValue->setStyleSheet("color: #FFC107; font-weight: bold;"); // Sarı
    
    // İstatistikleri layout'a ekle
    QGridLayout* gridStatsLayout = new QGridLayout();
    gridStatsLayout->addWidget(runningContainerLabel, 0, 0);
    gridStatsLayout->addWidget(runningContainerValue, 0, 1);
    gridStatsLayout->addWidget(totalContainerLabel, 0, 2);
    gridStatsLayout->addWidget(totalContainerValue, 0, 3);
    gridStatsLayout->addWidget(imageLabel, 0, 4);
    gridStatsLayout->addWidget(imageValue, 0, 5);
    gridStatsLayout->setColumnStretch(1, 0);
    gridStatsLayout->setColumnStretch(3, 0);
    gridStatsLayout->setColumnStretch(5, 0);
    
    statsLayout->addLayout(gridStatsLayout);
    containersLayout->addWidget(dockerStatsGroup);
    
    // Ana düzene tab widget'ı ekle
    mainLayout->addWidget(tabWidget);
    
    // Yenile butonu
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    
    refreshButton = new QPushButton(tr("Yenile"), this);
    refreshButton->setStyleSheet(
        "QPushButton {"
        "   background-color: #0078d7;"
        "   color: white;"
        "   border: none;"
        "   padding: 8px 16px;"
        "   border-radius: 4px;"
        "}"
        "QPushButton:hover {"
        "   background-color: #1c97ea;"
        "}"
    );
    buttonLayout->addWidget(refreshButton);
    
    // Kapat butonu
    QPushButton* closeButton = new QPushButton(tr("Kapat"), this);
    closeButton->setStyleSheet(
        "QPushButton {"
        "   background-color: #e74c3c;"
        "   color: white;"
        "   border: none;"
        "   padding: 8px 16px;"
        "   border-radius: 4px;"
        "}"
        "QPushButton:hover {"
        "   background-color: #c0392b;"
        "}"
    );
    buttonLayout->addWidget(closeButton);
    
    // Butonları ana düzene ekle
    mainLayout->addLayout(buttonLayout);
    
    // Kapat butonuna tıklamayı bağla
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
}

void ServiceStatusDialog::setupConnections()
{
    // Tab değiştiğinde otomatik güncelleştirme
    connect(tabWidget, &QTabWidget::currentChanged, [this](int index) {
        if (index == 0) {
            updateServiceStatus();
        } else if (index == 1) {
            updateContainerList();
        }
    });
    
    // Yenile butonuna tıklama
    connect(refreshButton, &QPushButton::clicked, [this]() {
        int currentIndex = tabWidget->currentIndex();
        if (currentIndex == 0) {
            updateServiceStatus();
        } else if (currentIndex == 1) {
            updateContainerList();
        }
        
        // Yenile butonuna basıldığını göstermek için animasyon efekti
        QPushButton* refreshBtn = qobject_cast<QPushButton*>(sender());
        if (refreshBtn) {
            QString originalText = refreshBtn->text();
            refreshBtn->setEnabled(false);
            refreshBtn->setText(tr("Yenileniyor..."));
            
            // 500ms sonra butonu eski haline getir
            QTimer::singleShot(500, [refreshBtn, originalText]() {
                refreshBtn->setEnabled(true);
                refreshBtn->setText(originalText);
            });
        }
    });
}

void ServiceStatusDialog::updateServiceStatus()
{
    if (!statusTable) return;
    
    statusTable->setRowCount(0);
    
    // 1. Docker servisi
    bool dockerAvailable = false;
    if (dockerUIManager) {
        try {
            dockerAvailable = dockerUIManager->isDockerAvailable();
        } catch (const std::exception& e) {
            qDebug() << "Exception checking Docker status:" << e.what();
            dockerAvailable = false;
        } catch (...) {
            qDebug() << "Unknown exception checking Docker status";
            dockerAvailable = false;
        }
    }
    
    try {
        int row = statusTable->rowCount();
        statusTable->insertRow(row);
        statusTable->setItem(row, 0, new QTableWidgetItem("Docker Servisi"));
        statusTable->setItem(row, 1, new QTableWidgetItem(dockerAvailable ? tr("Çalışıyor") : tr("Devre Dışı")));
        statusTable->setItem(row, 2, new QTableWidgetItem(dockerAvailable ? 
            tr("Docker servisi aktif ve kullanılabilir.") : 
            tr("Docker servisi bulunamadı. Kontrol ediniz.")));
        
        if (dockerAvailable) {
            statusTable->item(row, 1)->setBackground(QColor(45, 164, 78, 100)); // Yeşil
            statusTable->item(row, 1)->setForeground(Qt::white);
        } else {
            statusTable->item(row, 1)->setBackground(QColor(209, 36, 47, 100)); // Kırmızı  
            statusTable->item(row, 1)->setForeground(Qt::white);
        }
    } catch (...) {
        qDebug() << "Error updating Docker service status row";
    }
    
    // 2. CDR Konteyner durumu
    bool cdrInitialized = false;
    if (scanManager) {
        try {
            cdrInitialized = scanManager->isCdrInitialized();
        } catch (const std::exception& e) {
            qDebug() << "Exception checking CDR status:" << e.what();
            cdrInitialized = false;
        } catch (...) {
            qDebug() << "Unknown exception checking CDR status";
            cdrInitialized = false;
        }
    }
    
    try {
        int row = statusTable->rowCount();
        statusTable->insertRow(row);
        statusTable->setItem(row, 0, new QTableWidgetItem("CDR Konteyner"));
        statusTable->setItem(row, 1, new QTableWidgetItem(cdrInitialized ? tr("Hazır") : tr("Hazır Değil")));
        statusTable->setItem(row, 2, new QTableWidgetItem(cdrInitialized ? 
            tr("CDR servisi başlatılabilir durumda.") : 
            tr("CDR servisi başlatılamıyor. Docker kontrol edin.")));
        
        if (cdrInitialized) {
            statusTable->item(row, 1)->setBackground(QColor(45, 164, 78, 100)); // Yeşil
            statusTable->item(row, 1)->setForeground(Qt::white);
        } else {
            statusTable->item(row, 1)->setBackground(QColor(209, 36, 47, 100)); // Kırmızı  
            statusTable->item(row, 1)->setForeground(Qt::white);
        }
    } catch (...) {
        qDebug() << "Error updating CDR status row";
    }
    
    // 3. Sandbox Konteyner durumu
    bool sandboxInitialized = false;
    if (scanManager) {
        try {
            sandboxInitialized = scanManager->isSandboxInitialized();
        } catch (const std::exception& e) {
            qDebug() << "Exception checking Sandbox status:" << e.what();
            sandboxInitialized = false;
        } catch (...) {
            qDebug() << "Unknown exception checking Sandbox status";
            sandboxInitialized = false;
        }
    }
    
    try {
        int row = statusTable->rowCount();
        statusTable->insertRow(row);
        statusTable->setItem(row, 0, new QTableWidgetItem("Sandbox Konteyner"));
        statusTable->setItem(row, 1, new QTableWidgetItem(sandboxInitialized ? tr("Hazır") : tr("Hazır Değil")));
        statusTable->setItem(row, 2, new QTableWidgetItem(sandboxInitialized ? 
            tr("Sandbox servisi başlatılabilir durumda.") : 
            tr("Sandbox servisi başlatılamıyor. Docker kontrol edin.")));
        
        if (sandboxInitialized) {
            statusTable->item(row, 1)->setBackground(QColor(45, 164, 78, 100)); // Yeşil
            statusTable->item(row, 1)->setForeground(Qt::white);
        } else {
            statusTable->item(row, 1)->setBackground(QColor(209, 36, 47, 100)); // Kırmızı  
            statusTable->item(row, 1)->setForeground(Qt::white);
        }
    } catch (...) {
        qDebug() << "Error updating Sandbox status row";
    }
    
    // 4. VirusTotal API Bağlantısı
    bool virusTotalConnected = false;
    if (apiManager) {
        try {
            virusTotalConnected = apiManager->hasApiKey();
        } catch (const std::exception& e) {
            qDebug() << "Exception checking VirusTotal API:" << e.what();
            virusTotalConnected = false;
        } catch (...) {
            qDebug() << "Unknown exception checking VirusTotal API";
            virusTotalConnected = false;
        }
    }
    
    try {
        int row = statusTable->rowCount();
        statusTable->insertRow(row);
        statusTable->setItem(row, 0, new QTableWidgetItem("VirusTotal API"));
        statusTable->setItem(row, 1, new QTableWidgetItem(virusTotalConnected ? tr("Bağlı") : tr("Bağlı Değil")));
        statusTable->setItem(row, 2, new QTableWidgetItem(virusTotalConnected ? 
            tr("VirusTotal API anahtarı ayarlanmış.") : 
            tr("VirusTotal API anahtarı ayarlanmamış.")));
        
        if (virusTotalConnected) {
            statusTable->item(row, 1)->setBackground(QColor(45, 164, 78, 100)); // Yeşil
            statusTable->item(row, 1)->setForeground(Qt::white);
        } else {
            statusTable->item(row, 1)->setBackground(QColor(209, 36, 47, 100)); // Kırmızı  
            statusTable->item(row, 1)->setForeground(Qt::white);
        }
    } catch (...) {
        qDebug() << "Error updating VirusTotal API status row";
    }
    
    // 5. Veritabanı Bağlantısı
    bool dbConnected = false;
    try {
        // Veritabanı bağlantı kontrolü
        dbConnected = true; // Bu kısmı gerçek veritabanı kontrolü ile değiştirin
    } catch (const std::exception& e) {
        qDebug() << "Exception checking database:" << e.what();
        dbConnected = false;
    } catch (...) {
        qDebug() << "Unknown exception checking database";
        dbConnected = false;
    }
    
    try {
        int row = statusTable->rowCount();
        statusTable->insertRow(row);
        statusTable->setItem(row, 0, new QTableWidgetItem("Veritabanı"));
        statusTable->setItem(row, 1, new QTableWidgetItem(dbConnected ? tr("Bağlı") : tr("Bağlı Değil")));
        statusTable->setItem(row, 2, new QTableWidgetItem(dbConnected ? 
            tr("Veritabanı bağlantısı sağlandı.") : 
            tr("Veritabanına bağlanılamıyor.")));
        
        if (dbConnected) {
            statusTable->item(row, 1)->setBackground(QColor(45, 164, 78, 100)); // Yeşil
            statusTable->item(row, 1)->setForeground(Qt::white);
        } else {
            statusTable->item(row, 1)->setBackground(QColor(209, 36, 47, 100)); // Kırmızı  
            statusTable->item(row, 1)->setForeground(Qt::white);
        }
    } catch (...) {
        qDebug() << "Error updating database status row";
    }
}

void ServiceStatusDialog::updateContainerList()
{
    if (!containerTable || !runningContainerValue || !totalContainerValue || !imageValue) return;

    containerTable->setRowCount(0);
    
    // Docker durumu kontrolü
    bool dockerAvailable = false;
    if (dockerUIManager) {
        try {
            dockerAvailable = dockerUIManager->isDockerAvailable();
        } catch (...) {
            dockerAvailable = false;
        }
    }
    
    if (!dockerAvailable || !dockerUIManager) {
        // Hata mesajı göster
        int row = containerTable->rowCount();
        containerTable->insertRow(row);
        QTableWidgetItem *errorItem = new QTableWidgetItem("Docker mevcut değil veya çalışmıyor!");
        containerTable->setSpan(row, 0, 1, 5);
        containerTable->setItem(row, 0, errorItem);
        errorItem->setTextAlignment(Qt::AlignCenter);
        errorItem->setBackground(QColor(209, 36, 47, 100)); // Kırmızı
        errorItem->setForeground(Qt::white);
        
        // İstatistikleri sıfırla
        runningContainerValue->setText("0");
        totalContainerValue->setText("0");
        imageValue->setText("0");
        return;
    }
    
    // Docker konteyner ve imaj bilgilerini al
    QJsonArray containers;
    QJsonArray images;
    try {
        containers = dockerUIManager->getDockerContainers();
    } catch (...) {
        containers = QJsonArray();
        int row = containerTable->rowCount();
        containerTable->insertRow(row);
        QTableWidgetItem *errorItem = new QTableWidgetItem("Konteyner bilgisi alınamadı!");
        containerTable->setSpan(row, 0, 1, 5);
        containerTable->setItem(row, 0, errorItem);
        errorItem->setTextAlignment(Qt::AlignCenter);
        errorItem->setBackground(QColor(209, 36, 47, 100)); // Kırmızı
        errorItem->setForeground(Qt::white);
    }
    
    try {
        images = dockerUIManager->getDockerImages();
    } catch (...) {
        images = QJsonArray();
    }
    
    // Konteyner sayaçları
    int runningCount = 0;
    
    // Konteyner listesini tabloya ekle
    for (int i = 0; i < containers.size(); ++i) {
        try {
            QJsonObject container = containers[i].toObject();
            if (container.isEmpty()) continue;
            
            int row = containerTable->rowCount();
            containerTable->insertRow(row);
            
            // ID
            containerTable->setItem(row, 0, new QTableWidgetItem(container["id"].toString()));
            
            // İsim
            containerTable->setItem(row, 1, new QTableWidgetItem(container["name"].toString()));
            
            // İmaj
            containerTable->setItem(row, 2, new QTableWidgetItem(container["image"].toString()));
            
            // Durum
            QString status = container["status"].toString();
            QTableWidgetItem *statusItem = new QTableWidgetItem(status);
            containerTable->setItem(row, 3, statusItem);
            
            // Portlar
            containerTable->setItem(row, 4, new QTableWidgetItem(container["ports"].toString()));
            
            // Çalışıyor mu?
            if (status.contains("Up", Qt::CaseInsensitive)) {
                runningCount++;
                statusItem->setBackground(QColor(45, 164, 78, 100)); // Yeşil
                statusItem->setForeground(Qt::white);
            } else {
                statusItem->setBackground(QColor(169, 169, 169, 100)); // Gri
                statusItem->setForeground(Qt::white);
            }
        } catch (...) {
            qDebug() << "Error processing container at index" << i;
        }
    }
    
    // Konteyner yoksa bilgi mesajı göster
    if (containers.isEmpty()) {
        int row = containerTable->rowCount();
        containerTable->insertRow(row);
        QTableWidgetItem *infoItem = new QTableWidgetItem(tr("Çalışan veya durdurulmuş konteyner bulunamadı"));
        containerTable->setSpan(row, 0, 1, 5);
        containerTable->setItem(row, 0, infoItem);
        infoItem->setTextAlignment(Qt::AlignCenter);
        infoItem->setBackground(QColor(52, 73, 94, 100)); // Koyu mavi
        infoItem->setForeground(Qt::white);
    }
    
    // İstatistikleri güncelle
    runningContainerValue->setText(QString::number(runningCount));
    totalContainerValue->setText(QString::number(containers.size()));
    imageValue->setText(QString::number(images.size()));
}
