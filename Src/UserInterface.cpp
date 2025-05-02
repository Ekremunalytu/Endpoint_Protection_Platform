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
    
    // Durum bilgisi widget'ı - Her zaman sağ üstte olacak
    QWidget *statusWidget = new QWidget(this);
    statusWidget->setStyleSheet(
        "QWidget {"
        "    background-color: #14141a;"
        "    border-radius: 12px;"
        "    padding: 15px;"
        "}"
    );
    statusWidget->setFixedWidth(400);  // Genişliği sabitle
    statusWidget->setMinimumHeight(80); // Minimum yükseklik
    
    QHBoxLayout *statusLayout = new QHBoxLayout(statusWidget);
    statusLayout->setSpacing(15);
    
    // Durum bilgisi widget'ı
    QVBoxLayout *statusInfoLayout = new QVBoxLayout();
    statusInfoLayout->setSpacing(5);
    
    QLabel *statusTextLabel = new QLabel(tr("No threats detected"), this);
    statusTextLabel->setStyleSheet(
        "QLabel {"
        "    font-size: 18px;"
        "    font-weight: bold;"
        "    color: white;"
        "    text-align: right;"
        "}"
    );
    statusTextLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    statusInfoLayout->addWidget(statusTextLabel);
    
    QLabel *statusDescLabel = new QLabel(tr("Your device is being monitored and protected."), this);
    statusDescLabel->setStyleSheet(
        "QLabel {"
        "    font-size: 13px;"
        "    color: #aaaaaa;"
        "    text-align: right;"
        "}"
    );
    statusDescLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    statusInfoLayout->addWidget(statusDescLabel);
    
    statusLayout->addLayout(statusInfoLayout, 1);
    
    // Yeşil tik işareti ve durum metni - sağa taşındı
    QLabel *successIcon = new QLabel(this);
    QPixmap tickPixmap(80, 80); // Daha küçük bir tik işareti
    tickPixmap.fill(Qt::transparent);
    QPainter painter(&tickPixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(QPen(QColor("#2bbd7e"), 5));
    painter.setBrush(QColor("#2bbd7e"));
    painter.drawEllipse(15, 15, 50, 50);
    
    // Tik işareti çizimi
    QPainterPath path;
    path.moveTo(25, 40);
    path.lineTo(35, 50);
    path.lineTo(55, 30);
    painter.setPen(QPen(Qt::white, 5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawPath(path);
    
    successIcon->setPixmap(tickPixmap);
    successIcon->setAlignment(Qt::AlignCenter);
    statusLayout->addWidget(successIcon, 0, Qt::AlignCenter);
    
    // Layout'lara ekle
    headerAreaLayout->addWidget(titleWidget, 1);  // Sol tarafta başlık
    headerAreaLayout->addStretch(0);  // Esnek boşluk ekle
    headerAreaLayout->addWidget(statusWidget, 0); // Sağ tarafta durum bilgisi (sıkıştırılmaz)
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
        resultsWidget->setVisible(true);
        apiGroup->setVisible(true);
        detailedResultScrollArea->setVisible(false);
        resultScrollArea->setVisible(true);
        
        // VirusTotal tarama işlemini başlat
        this->onsendVirusTotalButtonClicked();
    });
    
    // CDR taraması butonu için bağlantı
    connect(cdrScanBtn, &QPushButton::clicked, [this, resultsWidget, apiGroup, detailedResultScrollArea, resultScrollArea]() {
        resultsWidget->setVisible(true);
        apiGroup->setVisible(true);
        detailedResultScrollArea->setVisible(false);
        resultScrollArea->setVisible(true);
        
        // CDR işlemini başlat
        this->onCdrButtonClicked();
    });
    
    // Sandbox butonu için bağlantı
    connect(sandboxBtn, &QPushButton::clicked, [this, resultsWidget, apiGroup, detailedResultScrollArea, resultScrollArea]() {
        resultsWidget->setVisible(true);
        apiGroup->setVisible(true);
        detailedResultScrollArea->setVisible(false);
        resultScrollArea->setVisible(true);
        
        // Sandbox analiz işlemini başlat
        this->onSandboxButtonClicked();
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
