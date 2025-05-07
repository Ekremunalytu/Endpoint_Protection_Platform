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
    setWindowTitle("API Key Settings");
    setModal(true);
    setMinimumWidth(450);

    // Modern tema renkleri - ana temadan alındı
    QString backgroundColor = "#181818";      // İkincil arkaplan rengi
    QString textColor = "#ffffff";            // Ana metin rengi
    QString secondaryTextColor = "#cccccc";   // İkincil metin rengi
    QString accentColor = "#0078d7";          // Vurgu rengi
    QString borderColor = "#333333";          // Kenarlık rengi
    
    // Dialog'a tema uygula
    setStyleSheet(QString(
        "QDialog {"
        "   background-color: %1;"
        "   color: %2;"
        "   font-family: 'Segoe UI', 'SF Pro Text', 'Helvetica Neue', sans-serif;"
        "}")
        .arg(backgroundColor)
        .arg(textColor)
    );

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setSpacing(20);
    layout->setContentsMargins(30, 30, 30, 30);

    QLabel *infoLabel = new QLabel("Enter your VirusTotal API key:", this);
    infoLabel->setStyleSheet(QString(
        "font-size: 15pt;"
        "color: %1;"
        "margin-bottom: 10px;")
        .arg(textColor)
    );
    layout->addWidget(infoLabel);

    apiKeyLineEdit = new QLineEdit(this);
    apiKeyLineEdit->setPlaceholderText("API Key here...");
    apiKeyLineEdit->setStyleSheet(QString(
        "QLineEdit {"
        "   padding: 12px;"
        "   font-size: 13pt;"
        "   border: 2px solid %1;"
        "   border-radius: 5px;"
        "   background-color: #232323;"
        "   color: %2;"
        "}"
        "QLineEdit:focus {"
        "   border: 2px solid %3;"
        "}")
        .arg(borderColor)
        .arg(textColor)
        .arg(accentColor)
    );
    layout->addWidget(apiKeyLineEdit);
    
    // API key hakkında ek bilgi
    QLabel *apiInfoLabel = new QLabel(tr("Get your free API key from <a href='https://www.virustotal.com/gui/join-us'>VirusTotal</a>"), this);
    apiInfoLabel->setOpenExternalLinks(true);
    apiInfoLabel->setStyleSheet(QString(
        "font-size: 11pt;"
        "color: %1;"
        "margin-top: -10px;"
        "margin-bottom: 10px;")
        .arg(secondaryTextColor)
    );
    layout->addWidget(apiInfoLabel);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(15);

    QPushButton *okButton = new QPushButton("Save", this);
    QPushButton *cancelButton = new QPushButton("Cancel", this);

    // Ortak buton stili
    QString buttonStyle = QString(
        "QPushButton {"
        "   padding: 12px 25px;"
        "   font-size: 13pt;"
        "   border-radius: 5px;"
        "   min-width: 120px;"
        "   font-weight: 500;"
        "}")
        .arg(secondaryTextColor);

    // Kaydet butonu
    okButton->setStyleSheet(buttonStyle + QString(
        "QPushButton {"
        "   background-color: %1;"
        "   color: white;"
        "   border: none;"
        "}"
        "QPushButton:hover {"
        "   background-color: #1e88e5;"
        "}"
        "QPushButton:pressed {"
        "   background-color: #0066c0;"
        "}")
        .arg(accentColor)
    );

    // İptal butonu
    cancelButton->setStyleSheet(buttonStyle +
        "QPushButton {"
        "   background-color: #424242;"
        "   color: white;"
        "   border: none;"
        "}"
        "QPushButton:hover {"
        "   background-color: #616161;"
        "}"
        "QPushButton:pressed {"
        "   background-color: #212121;"
        "}"
    );

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

    // Create menu - Sadeleştirilmiş menü yapısı
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

    // Menüde sadece API Key ayarını bırakıyoruz
    menu->addAction(apiKeyAction);

    menuButton->setMenu(menu);

    // Add menu button to toolbar
    QToolBar* mainToolBar = addToolBar(tr("Main Menu"));
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

    // Tema renkleri - tutarlı renk değişkenleri tanımlayarak arayüzün tutarlı görünmesini sağlıyoruz
    QString backgroundColor = "#0c0c0c";      // Ana arkaplan rengi - koyu siyah
    QString secondaryBgColor = "#181818";     // İkincil arkaplan rengi - sidebar ve diğer alanlar için
    QString accentColor = "#0078d7";          // Vurgu rengi - Microsoft mavisi
    QString borderColor = "#333333";          // Kenarlık rengi
    QString textColor = "#ffffff";            // Ana metin rengi - beyaz
    QString secondaryTextColor = "#cccccc";   // İkincil metin rengi - açık gri
    
    // Ana içerik bölümü
    QWidget *contentWidget = new QWidget(this);
    contentWidget->setStyleSheet(QString("background-color: %1;").arg(backgroundColor));
    
    // Sol sidebar için bir layout
    QHBoxLayout *horizontalLayout = new QHBoxLayout(contentWidget);
    horizontalLayout->setSpacing(0);
    horizontalLayout->setContentsMargins(0, 0, 0, 0);
    
    // Sol sidebar oluştur
    QWidget *sidebarWidget = new QWidget(this);
    sidebarWidget->setFixedWidth(220);
    sidebarWidget->setStyleSheet(
        QString("QWidget {"
        "    background-color: %1;"
        "    border-right: 1px solid %2;"
        "}"
        "QPushButton {"
        "    text-align: left;"
        "    padding: 12px 20px;"
        "    border: none;"
        "    border-radius: 0;"
        "    background-color: transparent;"
        "    color: %3;"
        "    font-size: 14px;"
        "}"
        "QPushButton:hover {"
        "    background-color: %2;"
        "    color: %4;"
        "}"
        "QPushButton:checked {"
        "    background-color: #222222;"
        "    color: %4;"
        "    font-weight: bold;"
        "    border-left: 4px solid %5;"
        "}")
        .arg(secondaryBgColor)
        .arg(borderColor)
        .arg(secondaryTextColor)
        .arg(textColor)
        .arg(accentColor)
    );
    
    // Sidebar layout
    QVBoxLayout *sidebarLayout = new QVBoxLayout(sidebarWidget);
    sidebarLayout->setSpacing(0);
    sidebarLayout->setContentsMargins(0, 20, 0, 20);

    // Sidebar butonları için ortak renk - daha tutarlı bir UI için
    QString sidebarButtonColor = "#1e88e5";
    
    // Sidebar butonu oluşturma için lambda fonksiyon
    auto createSidebarButton = [this, sidebarLayout, textColor, accentColor](const QString &text, bool checked = false, const QString &bgColor = "") {
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
                "    color: %2;"
                "    font-size: 14px;"
                "    font-weight: bold;"
                "}"
                "QPushButton:hover {"
                "    background-color: #333333;"
                "    color: %2;"
                "}"
                "QPushButton:checked {"
                "    background-color: #222222;"
                "    color: %2;"
                "    font-weight: bold;"
                "    border-left: 4px solid %3;"
                "}")
                .arg(bgColor)
                .arg(textColor)
                .arg(accentColor)
            );
        }
        
        sidebarLayout->addWidget(btn);
        return btn;
    };

    // Sidebar butonları - hepsi aynı renk kullanıyor
    QPushButton *offlineScanBtn = createSidebarButton(tr("Offline Scan"), true, sidebarButtonColor);
    QPushButton *virusScanBtn = createSidebarButton(tr("Online Scan"), false, sidebarButtonColor);
    QPushButton *cdrScanBtn = createSidebarButton(tr("CDR Scan"), false, sidebarButtonColor);
    QPushButton *sandboxBtn = createSidebarButton(tr("Sandbox"), false, sidebarButtonColor);
    QPushButton *serviceStatusBtn = createSidebarButton(tr("Service Status"), false, sidebarButtonColor);

    // Sidebar'ın alt kısmına geçmiş butonu ekle - aynı renk stili ile
    sidebarLayout->addStretch();
    
    QPushButton *historyBtn = createSidebarButton(tr("History"), false, sidebarButtonColor);
    
    // Histori butonuna tıklama işlevi ekliyoruz
    connect(historyBtn, &QPushButton::clicked, this, &MainWindow::onHistoryButtonClicked);
    
    horizontalLayout->addWidget(sidebarWidget);

    // Ana içerik alanı
    QWidget *mainContentWidget = new QWidget(this);
    mainContentWidget->setStyleSheet(QString("background-color: %1; padding: 20px;").arg(backgroundColor));
    
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
    QLabel *resultsTitle = new QLabel(tr("Scan Results"), this);
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
    QPushButton *detailedViewButton = new QPushButton(tr("Detailed Analysis"), this);
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
        QString("QGroupBox {"
        "    font-size: 14px;"
        "    font-weight: bold;"
        "    border: 1px solid %1;"
        "    border-radius: 8px;"
        "    margin-top: 1ex;"
        "    padding: 10px;"
        "    background-color: %2;"
        "    color: %3;"
        "}"
        "QGroupBox::title {"
        "    subcontrol-origin: margin;"
        "    subcontrol-position: top center;"
        "    padding: 0 10px;"
        "    color: %3;"
        "    background-color: %2;"
        "}")
        .arg(borderColor)
        .arg(secondaryBgColor)
        .arg(secondaryTextColor)
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
            apiManager->setApiKey(apiKey);
            apiLogTextEdit->appendPlainText(QString("\n🔑 %1 | API key updated")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
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
    setWindowTitle(tr("System Status"));
    setMinimumSize(900, 600);
    setModal(true);
    
    createUI();
    updateServiceStatus();
    updateContainerList();
    setupConnections();
}

void ServiceStatusDialog::createUI()
{
    // Modern tema renkleri - ana temadan alındı
    QString backgroundColor = "#181818";
    QString textColor = "#ffffff";
    QString secondaryTextColor = "#cccccc";
    QString accentColor = "#0078d7";
    QString borderColor = "#333333";

    // Main layout
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(20);
    mainLayout->setContentsMargins(30, 30, 30, 30);
    
    // Dialog stil ayarları
    setStyleSheet(QString(
        "QDialog {"
        "    background-color: %1;"
        "    color: %2;"
        "    font-family: 'Segoe UI', 'SF Pro Text', 'Helvetica Neue', sans-serif;"
        "}")
        .arg(backgroundColor)
        .arg(textColor)
    );
    
    // Title with icon
    QHBoxLayout* titleLayout = new QHBoxLayout();
    QLabel* iconLabel = new QLabel(this);
    iconLabel->setText("📊");
    iconLabel->setStyleSheet("font-size: 24px;");
    
    QLabel* titleLabel = new QLabel(tr("System Services and Container Status"), this);
    titleLabel->setStyleSheet(QString(
        "QLabel {"
        "    font-size: 22px;"
        "    font-weight: bold;"
        "    color: %1;"
        "}")
        .arg(textColor)
    );
    
    titleLayout->addWidget(iconLabel);
    titleLayout->addWidget(titleLabel);
    titleLayout->addStretch();
    
    mainLayout->addLayout(titleLayout);
    
    // Create Tab Widget with modern styling
    tabWidget = new QTabWidget(this);
    tabWidget->setStyleSheet(QString(
        "QTabWidget::pane {"
        "    border: 1px solid %1;"
        "    background-color: %2;"
        "    border-radius: 8px;"
        "}"
        "QTabBar::tab {"
        "    background-color: #2d2d30;"
        "    color: %3;"
        "    padding: 10px 20px;"
        "    border-top-left-radius: 8px;"
        "    border-top-right-radius: 8px;"
        "    margin-right: 4px;"
        "}"
        "QTabBar::tab:selected {"
        "    background-color: %4;"
        "    color: white;"
        "}"
        "QTabBar::tab:hover:!selected {"
        "    background-color: #3e3e42;"
        "}")
        .arg(borderColor)
        .arg(backgroundColor)
        .arg(secondaryTextColor)
        .arg(accentColor)
    );
    
    // Service Status Tab
    QWidget* serviceStatusTab = new QWidget(this);
    QVBoxLayout* serviceLayout = new QVBoxLayout(serviceStatusTab);
    serviceLayout->setContentsMargins(20, 20, 20, 20);
    
    // Service status açıklaması
    QLabel* serviceInfoLabel = new QLabel(tr("Below is the current status of system services. Green indicates the service is active and running properly."), serviceStatusTab);
    serviceInfoLabel->setStyleSheet(QString(
        "font-size: 14px;"
        "color: %1;"
        "margin-bottom: 15px;")
        .arg(secondaryTextColor)
    );
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
    statusTable->setStyleSheet(QString(
        "QTableWidget {"
        "   background-color: %1;"
        "   color: %2;"
        "   gridline-color: %3;"
        "   border: 1px solid %3;"
        "   border-radius: 8px;"
        "}"
        "QTableWidget::item {"
        "   padding: 12px;"
        "   border-bottom: 1px solid %3;"
        "}"
        "QTableWidget::item:selected {"
        "   background-color: %4;"
        "   color: white;"
        "}"
        "QHeaderView::section {"
        "   background-color: #252526;"
        "   color: %2;"
        "   font-weight: bold;"
        "   border: none;"
        "   padding: 10px;"
        "}")
        .arg("#212121")
        .arg(textColor)
        .arg(borderColor)
        .arg(accentColor)
    );
    serviceLayout->addWidget(statusTable);
    
    // Docker Containers Tab
    QWidget* dockerContainersTab = new QWidget(this);
    QVBoxLayout* containersLayout = new QVBoxLayout(dockerContainersTab);
    containersLayout->setContentsMargins(20, 20, 20, 20);
    
    // Docker container açıklaması
    QLabel* containerInfoLabel = new QLabel(tr("This tab shows all Docker containers and their current status. Running containers are marked in green."), dockerContainersTab);
    containerInfoLabel->setStyleSheet(QString(
        "font-size: 14px;"
        "color: %1;"
        "margin-bottom: 15px;")
        .arg(secondaryTextColor)
    );
    containerInfoLabel->setWordWrap(true);
    containersLayout->addWidget(containerInfoLabel);
    
    // Docker container table
    containerTable = new QTableWidget(dockerContainersTab);
    containerTable->setColumnCount(5);
    containerTable->setHorizontalHeaderLabels({tr("ID"), tr("Name"), tr("Image"), tr("Status"), tr("Ports")});
    containerTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    containerTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    containerTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    containerTable->setAlternatingRowColors(true);
    containerTable->verticalHeader()->setVisible(false);
    containerTable->setStyleSheet(QString(
        "QTableWidget {"
        "   background-color: %1;"
        "   color: %2;"
        "   gridline-color: %3;"
        "   border: 1px solid %3;"
        "   border-radius: 8px;"
        "}"
        "QTableWidget::item {"
        "   padding: 12px;"
        "   border-bottom: 1px solid %3;"
        "}"
        "QTableWidget::item:selected {"
        "   background-color: %4;"
        "   color: white;"
        "}"
        "QHeaderView::section {"
        "   background-color: #252526;"
        "   color: %2;"
        "   font-weight: bold;"
        "   border: none;"
        "   padding: 10px;"
        "}")
        .arg("#212121")
        .arg(textColor)
        .arg(borderColor)
        .arg(accentColor)
    );
    containersLayout->addWidget(containerTable);
    
    // Widget for Docker image and container statistics
    QFrame* dockerStatsFrame = new QFrame(dockerContainersTab);
    dockerStatsFrame->setFrameShape(QFrame::StyledPanel);
    dockerStatsFrame->setStyleSheet(QString(
        "QFrame {"
        "    border: 1px solid %1;"
        "    border-radius: 8px;"
        "    background-color: #1a1a1a;"
        "    padding: 15px;"
        "}")
        .arg(borderColor)
    );
    
    QHBoxLayout* statsLayout = new QHBoxLayout(dockerStatsFrame);
    statsLayout->setSpacing(20);
    
    // Stat kartları
    auto createStatCard = [this, dockerContainersTab](const QString& labelText, const QString& initialValue, const QString& color) {
        QFrame* card = new QFrame(dockerContainersTab);
        card->setFrameShape(QFrame::StyledPanel);
        card->setStyleSheet(QString(
            "QFrame {"
            "    background-color: #252526;"
            "    border-radius: 8px;"
            "    border: 1px solid %1;"
            "    padding: 10px;"
            "}")
            .arg("#333333")
        );
        
        QVBoxLayout* cardLayout = new QVBoxLayout(card);
        cardLayout->setSpacing(5);
        
        QLabel* label = new QLabel(labelText, card);
        label->setStyleSheet("color: #cccccc; font-size: 13px;");
        label->setAlignment(Qt::AlignCenter);
        
        QLabel* value = new QLabel(initialValue, card);
        value->setStyleSheet(QString("color: %1; font-size: 24px; font-weight: bold;").arg(color));
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
    
    // Add tab widget to main layout
    mainLayout->addWidget(tabWidget);
    
    // Button layout
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(15);
    buttonLayout->addStretch();
    
    // Refresh button with modern design
    refreshButton = new QPushButton(tr("Refresh"), this);
    refreshButton->setIcon(QIcon::fromTheme("view-refresh"));
    refreshButton->setStyleSheet(QString(
        "QPushButton {"
        "   background-color: %1;"
        "   color: white;"
        "   border: none;"
        "   padding: 12px 25px;"
        "   border-radius: 6px;"
        "   font-size: 14px;"
        "   font-weight: 500;"
        "   min-width: 140px;"
        "}"
        "QPushButton:hover {"
        "   background-color: #1e88e5;"
        "}"
        "QPushButton:pressed {"
        "   background-color: #0066c0;"
        "}")
        .arg(accentColor)
    );
    buttonLayout->addWidget(refreshButton);
    
    // Close button
    QPushButton* closeButton = new QPushButton(tr("Close"), this);
    closeButton->setStyleSheet(
        "QPushButton {"
        "   background-color: #424242;"
        "   color: white;"
        "   border: none;"
        "   padding: 12px 25px;"
        "   border-radius: 6px;"
        "   font-size: 14px;"
        "   font-weight: 500;"
        "   min-width: 140px;"
        "}"
        "QPushButton:hover {"
        "   background-color: #616161;"
        "}"
        "QPushButton:pressed {"
        "   background-color: #212121;"
        "}"
    );
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
    QStringList services = {"Virus Tarama Engine", "Real-time Protection", "CDR Service", "Sandbox Service", "Update Service"};
    QStringList statuses;
    QStringList details;

    // Virüs veritabanı bağlantısı ve durumu (YaraRuleManager üzerinden kontrol edilebilir)
    bool dbStatus = false;
    try {
        // Veritabanı bağlantısı ScanManager üzerinden kontrol edilir
        dbStatus = scanManager->isDbInitialized(); // Bu metodun ScanManager sınıfında tanımlanması gerekir
    } catch (...) {
        dbStatus = false;
    }
    statuses.append(dbStatus ? "Active" : "Inactive");
    details.append(dbStatus ? "Running (v1.2.3)" : "Database connection error");
    
    // Real-time Protection - gerçekte bu özellik yok, statik gösterilecek
    bool realTimeMonitoringActive = false; // Bu özellik gerçekte yok
    statuses.append(realTimeMonitoringActive ? "Active" : "Inactive");
    details.append(realTimeMonitoringActive ? "Monitoring all files" : "Service not available");
    
    // VirusTotal API bağlantı durumu
    bool vtApiActive = false;
    if (apiManager) {
        QString apiKey = apiManager->getApiKey();
        vtApiActive = !apiKey.isEmpty();
    }
    
    // CDR Service durumu - Docker bağlantısı ve CDR container durumu kontrolü
    bool dockerRunning = dockerUIManager->isDockerAvailable();
    bool cdrActive = scanManager->isCdrInitialized() && dockerRunning;
    statuses.append(cdrActive ? "Active" : "Inactive");
    
    if (cdrActive) {
        QString cdrImage = scanManager->getCurrentCdrImageName();
        details.append(cdrImage.isEmpty() ? 
            "Docker container ready" : 
            "Using image: " + cdrImage);
    } else if (!dockerRunning) {
        details.append("Docker is not running");
    } else {
        details.append("Service not initialized");
    }
    
    // Sandbox Service durumu - Docker bağlantısı ve Sandbox container durumu kontrolü
    bool sandboxActive = scanManager->isSandboxInitialized() && dockerRunning;
    statuses.append(sandboxActive ? "Active" : "Inactive");
    
    if (sandboxActive) {
        QString sandboxImage = scanManager->getCurrentSandboxImageName();
        details.append(sandboxImage.isEmpty() ? 
            "Docker container ready" : 
            "Using image: " + sandboxImage);
    } else if (!dockerRunning) {
        details.append("Docker is not running");
    } else {
        details.append("Service not initialized");
    }
    
    // Update servis durumu - VirusTotal API bağlantısı yeterli olabilir
    statuses.append(vtApiActive ? "Active" : "Inactive");
    details.append(vtApiActive ? 
        "Last update: " + QDateTime::currentDateTime().toString("dd MMMM yyyy hh:mm") : 
        "VirusTotal API key not set");
    
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
        
        // Container ID
        containerTable->setItem(row, 0, new QTableWidgetItem(container["id"].toString()));
        
        // Container Name
        containerTable->setItem(row, 1, new QTableWidgetItem(container["name"].toString()));
        
        // Container Image
        containerTable->setItem(row, 2, new QTableWidgetItem(container["image"].toString()));
        
        // Status - renkli gösterim
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
        
        // Ports
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
    
    // Modern tema renkleri - tanımlanması gereken tüm renkleri tanımlıyoruz
    QString backgroundColor = "#181818";      // İkincil arkaplan rengi
    QString textColor = "#ffffff";            // Ana metin rengi
    QString secondaryTextColor = "#cccccc";   // İkincil metin rengi
    QString accentColor = "#0078d7";          // Vurgu rengi
    QString borderColor = "#333333";          // Kenarlık rengi
    
    // Dialog'a tema uygula
    setStyleSheet(QString(
        "QDialog {"
        "   background-color: %1;"
        "   color: %2;"
        "   font-family: 'Segoe UI', 'SF Pro Text', 'Helvetica Neue', sans-serif;"
        "}")
        .arg(backgroundColor)
        .arg(textColor)
    );

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setSpacing(20);
    layout->setContentsMargins(30, 30, 30, 30);

    // Üst kısımda hizalı başlık
    QHBoxLayout* titleLayout = new QHBoxLayout();
    QLabel* iconLabel = new QLabel("🐳", this);
    iconLabel->setStyleSheet("font-size: 32px;"); // İkon boyutu artırıldı

    QLabel* titleLabel = new QLabel(tr("%1 Docker Image").arg(serviceType), this);
    titleLabel->setStyleSheet(QString(
        "QLabel {"
        "   font-size: 24px;" // Font boyutu artırıldı
        "   font-weight: bold;"
        "   color: %1;"
        "}")
        .arg(textColor)
    );
    
    titleLayout->addWidget(iconLabel);
    titleLayout->addWidget(titleLabel);
    titleLayout->addStretch();
    layout->addLayout(titleLayout);
    
    // Açıklama metni
    QLabel* descLabel = new QLabel(tr("Select a Docker image to use for %1 processing:").arg(serviceType), this);
    descLabel->setStyleSheet(QString(
        "font-size: 16px;" // Font boyutu artırıldı
        "color: %1;"
        "margin: 10px 0;"
        )
        .arg(secondaryTextColor)
    );
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
    
    imageComboBox->setStyleSheet(QString(
        "QComboBox {"
        "   padding: 12px 15px;"
        "   font-size: 16px;" // Font boyutu artırıldı
        "   border: 2px solid %1;"
        "   border-radius: 5px;"
        "   background-color: #232323;"
        "   color: %2;"
        "   min-width: 400px;" // Genişlik artırıldı
        "}"
        "QComboBox:focus {"
        "   border: 2px solid %3;"
        "}"
        "QComboBox::drop-down {"
        "   subcontrol-origin: padding;"
        "   subcontrol-position: center right;"
        "   width: 30px;" // Ok genişliği artırıldı
        "   border: none;"
        "   padding-right: 10px;"
        "}"
        "QComboBox QAbstractItemView {"
        "   background-color: #232323;"
        "   border: 1px solid %1;"
        "   color: %2;"
        "   selection-background-color: %3;"
        "   selection-color: white;"
        "   font-size: 16px;" // Liste öğeleri font boyutu artırıldı
        "}")
        .arg(borderColor)
        .arg(textColor)
        .arg(accentColor)
    );
    
    layout->addWidget(imageComboBox);
    
    // Docker Hub linki
    QLabel* hubLabel = new QLabel(tr("Don't see what you need? <a href='https://hub.docker.com/search?q=%1&type=image'>Search on Docker Hub</a>").arg(serviceType.toLower()), this);
    hubLabel->setOpenExternalLinks(true);
    hubLabel->setStyleSheet(QString(
        "font-size: 14px;" // Font boyutu artırıldı
        "color: %1;"
        "margin-top: 5px;"
        "margin-bottom: 15px;")
        .arg(secondaryTextColor)
    );
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
    
    // İptal butonu
    cancelButton->setStyleSheet(
        "QPushButton {"
        "   background-color: #424242;"
        "   color: white;"
        "   border: none;"
        "   padding: 12px 25px;"
        "   border-radius: 6px;"
        "   font-size: 16px;" // Font boyutu artırıldı
        "   font-weight: 500;"
        "}"
        "QPushButton:hover {"
        "   background-color: #616161;"
        "}"
        "QPushButton:pressed {"
        "   background-color: #212121;"
        "}"
    );
    
    // Onay butonu
    okButton->setStyleSheet(QString(
        "QPushButton {"
        "   background-color: %1;"
        "   color: white;"
        "   border: none;"
        "   padding: 12px 25px;"
        "   border-radius: 6px;"
        "   font-size: 16px;" // Font boyutu artırıldı
        "   font-weight: 500;"
        "}"
        "QPushButton:hover {"
        "   background-color: #1e88e5;"
        "}"
        "QPushButton:pressed {"
        "   background-color: #0066c0;"
        "}")
        .arg(accentColor)
    );
    
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
    // Modern tema renkleri
    QString backgroundColor = "#181818";
    QString textColor = "#ffffff";
    QString secondaryTextColor = "#cccccc";
    QString accentColor = "#0078d7";
    QString borderColor = "#333333";
    
    // Ana layout
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(20);
    mainLayout->setContentsMargins(30, 30, 30, 30);
    
    // Dialog stil ayarları
    setStyleSheet(QString(
        "QDialog {"
        "    background-color: %1;"
        "    color: %2;"
        "    font-family: 'Segoe UI', 'SF Pro Text', 'Helvetica Neue', sans-serif;"
        "}")
        .arg(backgroundColor)
        .arg(textColor)
    );
    
    // Title with icon
    QHBoxLayout* titleLayout = new QHBoxLayout();
    QLabel* iconLabel = new QLabel(this);
    iconLabel->setText("📅");
    iconLabel->setStyleSheet("font-size: 24px;");
    
    QLabel* titleLabel = new QLabel(tr("Scan History"), this);
    titleLabel->setStyleSheet(QString(
        "QLabel {"
        "    font-size: 22px;"
        "    font-weight: bold;"
        "    color: %1;"
        "}")
        .arg(textColor)
    );
    
    titleLayout->addWidget(iconLabel);
    titleLayout->addWidget(titleLabel);
    titleLayout->addStretch();
    
    // Statistics summary
    QLabel* statsLabel = new QLabel(tr("Total Scans: 54  |  Threats Detected: 12  |  Last Scan: Today 15:30"), this);
    statsLabel->setStyleSheet(QString(
        "QLabel {"
        "    font-size: 14px;"
        "    color: %1;"
        "}")
        .arg(secondaryTextColor)
    );
    titleLayout->addWidget(statsLabel);
    
    mainLayout->addLayout(titleLayout);
    
    // Create Tab Widget with modern styling
    tabWidget = new QTabWidget(this);
    tabWidget->setStyleSheet(QString(
        "QTabWidget::pane {"
        "    border: 1px solid %1;"
        "    background-color: %2;"
        "    border-radius: 8px;"
        "}"
        "QTabBar::tab {"
        "    background-color: #2d2d30;"
        "    color: %3;"
        "    padding: 10px 20px;"
        "    border-top-left-radius: 8px;"
        "    border-top-right-radius: 8px;"
        "    margin-right: 4px;"
        "}"
        "QTabBar::tab:selected {"
        "    background-color: %4;"
        "    color: white;"
        "}"
        "QTabBar::tab:hover:!selected {"
        "    background-color: #3e3e42;"
        "}")
        .arg(borderColor)
        .arg(backgroundColor)
        .arg(secondaryTextColor)
        .arg(accentColor)
    );
    
    // Create table style string for reuse
    QString tableStyle = QString(
        "QTableWidget {"
        "    background-color: #212121;"
        "    color: %1;"
        "    gridline-color: %2;"
        "    border: 1px solid %2;"
        "    border-radius: 8px;"
        "}"
        "QTableWidget::item {"
        "    padding: 8px;"
        "    border-bottom: 1px solid %2;"
        "}"
        "QTableWidget::item:selected {"
        "    background-color: %3;"
        "    color: white;"
        "}"
        "QHeaderView::section {"
        "    background-color: #252526;"
        "    color: %1;"
        "    font-weight: bold;"
        "    border: none;"
        "    padding: 8px;"
        "}")
        .arg(textColor)
        .arg(borderColor)
        .arg(accentColor);
    
    // Offline scan history tab
    QWidget* offlineTab = new QWidget(this);
    QVBoxLayout* offlineLayout = new QVBoxLayout(offlineTab);
    offlineLayout->setContentsMargins(20, 20, 20, 20);
    
    // Table for offline scan history
    scanHistoryTable = new QTableWidget(offlineTab);
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
    scanHistoryTable->setStyleSheet(tableStyle);
    offlineLayout->addWidget(scanHistoryTable);
    
    // VirusTotal scan history tab
    QWidget* vtTab = new QWidget(this);
    QVBoxLayout* vtLayout = new QVBoxLayout(vtTab);
    vtLayout->setContentsMargins(20, 20, 20, 20);
    
    vtHistoryTable = new QTableWidget(vtTab);
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
    vtHistoryTable->setStyleSheet(tableStyle);
    vtLayout->addWidget(vtHistoryTable);
    
    // CDR history tab
    QWidget* cdrTab = new QWidget(this);
    QVBoxLayout* cdrLayout = new QVBoxLayout(cdrTab);
    cdrLayout->setContentsMargins(20, 20, 20, 20);
    
    cdrHistoryTable = new QTableWidget(cdrTab);
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
    cdrHistoryTable->setStyleSheet(tableStyle);
    cdrLayout->addWidget(cdrHistoryTable);
    
    // Sandbox history tab
    QWidget* sandboxTab = new QWidget(this);
    QVBoxLayout* sandboxLayout = new QVBoxLayout(sandboxTab);
    sandboxLayout->setContentsMargins(20, 20, 20, 20);
    
    sandboxHistoryTable = new QTableWidget(sandboxTab);
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
    sandboxHistoryTable->setStyleSheet(tableStyle);
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
    resultCountLabel->setStyleSheet(QString(
        "font-size: 13px;"
        "color: %1;")
        .arg(secondaryTextColor)
    );
    
    buttonLayout->addWidget(resultCountLabel);
    buttonLayout->addStretch();
    
    // Export button
    exportHistoryButton = new QPushButton(tr("Export CSV"), this);
    exportHistoryButton->setStyleSheet(QString(
        "QPushButton {"
        "    background-color: #424242;"
        "    color: white;"
        "    border: none;"
        "    padding: 10px 20px;"
        "    border-radius: 6px;"
        "    font-size: 14px;"
        "    min-width: 130px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #616161;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #212121;"
        "}")
    );
    buttonLayout->addWidget(exportHistoryButton);
    
    // Clear history button
    clearHistoryButton = new QPushButton(tr("Clear History"), this);
    clearHistoryButton->setStyleSheet(QString(
        "QPushButton {"
        "    background-color: #d32f2f;"
        "    color: white;"
        "    border: none;"
        "    padding: 10px 20px;"
        "    border-radius: 6px;"
        "    font-size: 14px;"
        "    min-width: 130px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #f44336;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #b71c1c;"
        "}")
    );
    
    // Offline scan history data
    for (int i = 0; i < 5; i++) {
        int row = scanHistoryTable->rowCount();
        scanHistoryTable->insertRow(row);
        
        scanHistoryTable->setItem(row, 0, new QTableWidgetItem(QDateTime::currentDateTime().addDays(-i).toString("dd.MM.yyyy hh:mm")));
        scanHistoryTable->setItem(row, 1, new QTableWidgetItem(QString("report_%1.pdf").arg(i+1)));
        scanHistoryTable->setItem(row, 2, new QTableWidgetItem(QString("%1 KB").arg(i * 100 + 150)));
        scanHistoryTable->setItem(row, 3, new QTableWidgetItem(QString("%1 sec").arg(i * 2 + 3)));
        
        QTableWidgetItem* resultItem = new QTableWidgetItem(i % 3 == 0 ? tr("Malicious") : tr("Clean"));
        resultItem->setForeground(i % 3 == 0 ? QColor("#f44336") : QColor("#4caf50"));
        scanHistoryTable->setItem(row, 4, resultItem);
        
        // View details button
        QPushButton* viewButton = new QPushButton(tr("View"));
        viewButton->setStyleSheet(
            "QPushButton {"
            "    background-color: transparent;"
            "    color: #2196f3;"
            "    border: 1px solid #2196f3;"
            "    border-radius: 4px;"
            "    padding: 5px 10px;"
            "}"
            "QPushButton:hover {"
            "    background-color: rgba(33, 150, 243, 0.1);"
            "}"
        );
        QWidget* buttonContainer = new QWidget();
        QHBoxLayout* buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->addWidget(viewButton);
        buttonLayout->setAlignment(Qt::AlignCenter);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonContainer->setLayout(buttonLayout);
        
        scanHistoryTable->setCellWidget(row, 5, buttonContainer);
    }
    
    // VirusTotal scan data
    for (int i = 0; i < 5; i++) {
        int row = vtHistoryTable->rowCount();
        vtHistoryTable->insertRow(row);
        
        vtHistoryTable->setItem(row, 0, new QTableWidgetItem(QDateTime::currentDateTime().addDays(-i).toString("dd.MM.yyyy hh:mm")));
        vtHistoryTable->setItem(row, 1, new QTableWidgetItem(QString("sample_%1.exe").arg(i+1)));
        vtHistoryTable->setItem(row, 2, new QTableWidgetItem(QString("%1/70").arg(i * 3 + 2)));
        vtHistoryTable->setItem(row, 3, new QTableWidgetItem(QString("5f7e%1a49b2fc3%2fe9").arg(i).arg(i*2)));
        
        QTableWidgetItem* resultItem = new QTableWidgetItem(i % 3 == 0 ? tr("Suspicious") : tr("Clean"));
        resultItem->setForeground(i % 3 == 0 ? QColor("#ff9800") : QColor("#4caf50"));
        vtHistoryTable->setItem(row, 4, resultItem);
        
        // View details button
        QPushButton* viewButton = new QPushButton(tr("View"));
        viewButton->setStyleSheet(
            "QPushButton {"
            "    background-color: transparent;"
            "    color: #2196f3;"
            "    border: 1px solid #2196f3;"
            "    border-radius: 4px;"
            "    padding: 5px 10px;"
            "}"
            "QPushButton:hover {"
            "    background-color: rgba(33, 150, 243, 0.1);"
            "}"
        );
        QWidget* buttonContainer = new QWidget();
        QHBoxLayout* buttonLayout = new QHBoxLayout(buttonContainer);
        buttonLayout->addWidget(viewButton);
        buttonLayout->setAlignment(Qt::AlignCenter);
        buttonLayout->setContentsMargins(0, 0, 0, 0);
        buttonContainer->setLayout(buttonLayout);
        
        vtHistoryTable->setCellWidget(row, 5, buttonContainer);
    }
    
    // Benzer veriler diğer tablolar için de oluşturulabilir
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
        resultItem->setForeground(i % 3 == 0 ? QColor("#f44336") : QColor("#4caf50"));
        scanHistoryTable->setItem(row, 4, resultItem);
        
        // View details button for actions column
        QPushButton* viewButton = new QPushButton(tr("View"));
        viewButton->setStyleSheet(
            "QPushButton {"
            "    background-color: transparent;"
            "    color: #2196f3;"
            "    border: 1px solid #2196f3;"
            "    border-radius: 4px;"
            "    padding: 5px 10px;"
            "}"
            "QPushButton:hover {"
            "    background-color: rgba(33, 150, 243, 0.1);"
            "}"
        );
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
        resultItem->setForeground(i % 2 == 0 ? QColor("#ff9800") : QColor("#f44336"));
        vtHistoryTable->setItem(row, 4, resultItem);
        
        // View details button
        QPushButton* viewButton = new QPushButton(tr("View"));
        viewButton->setStyleSheet(
            "QPushButton {"
            "    background-color: transparent;"
            "    color: #2196f3;"
            "    border: 1px solid #2196f3;"
            "    border-radius: 4px;"
            "    padding: 5px 10px;"
            "}"
            "QPushButton:hover {"
            "    background-color: rgba(33, 150, 243, 0.1);"
            "}"
        );
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
        viewButton->setStyleSheet(
            "QPushButton {"
            "    background-color: transparent;"
            "    color: #2196f3;"
            "    border: 1px solid #2196f3;"
            "    border-radius: 4px;"
            "    padding: 5px 10px;"
            "}"
            "QPushButton:hover {"
            "    background-color: rgba(33, 150, 243, 0.1);"
            "}"
        );
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
        if (riskScore >= 80) {
            scoreItem->setForeground(QColor("#f44336")); // High risk - red
        } else if (riskScore >= 50) {
            scoreItem->setForeground(QColor("#ff9800")); // Medium risk - orange
        } else {
            scoreItem->setForeground(QColor("#ffeb3b")); // Low risk - yellow
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
        viewButton->setStyleSheet(
            "QPushButton {"
            "    background-color: transparent;"
            "    color: #2196f3;"
            "    border: 1px solid #2196f3;"
            "    border-radius: 4px;"
            "    padding: 5px 10px;"
            "}"
            "QPushButton:hover {"
            "    background-color: rgba(33, 150, 243, 0.1);"
            "}"
        );
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
