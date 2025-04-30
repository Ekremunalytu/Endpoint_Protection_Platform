#include "../Headers/UserInterface.h"
#include "../Headers/DbManager.h"
#include "../Headers/HashCalculation.h"
#include "../Headers/ApiManager.h"
#include "../Headers/YaraRuleManager.h"

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
      apiManager(nullptr),
      yaraManager(nullptr)
{
    apiManager = ApiManager::getInstance(this);
    yaraManager = new YaraRuleManager();
    yaraManager->initialize(); // YARA altyapısını başlat
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

    setWindowTitle(tr("Windows Antivirus"));
}

MainWindow::~MainWindow()
{
    if (yaraManager) delete yaraManager;
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
    connect(cdrAction, &QAction::triggered, [this](){
        QMessageBox::information(this, tr("CDR"), tr("Content Disarm and Reconstruction taraması henüz hazır değil."));
    });
    
    // Yeni Sandbox aksiyonu
    sandboxAction = new QAction(tr("Sandbox Analizi"), this);
    sandboxAction->setIcon(QIcon::fromTheme("system-run"));
    connect(sandboxAction, &QAction::triggered, [this](){
        QMessageBox::information(this, tr("Sandbox"), tr("Sandbox analiz işlemi henüz hazır değil."));
    });

    apiKeyAction = new QAction(tr("API Key Ayarla"), this);
    apiKeyAction->setIcon(QIcon::fromTheme("dialog-password"));
    connect(apiKeyAction, &QAction::triggered, this, &MainWindow::onApiKeyButtonClicked);
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
    menu->addAction(cdrAction);        // CDR butonunu ekledim
    menu->addAction(sandboxAction);    // Sandbox butonunu ekledim
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
    setupTextEditStyle(resultTextEdit);
    resultTextEdit->setMinimumHeight(1600); // 800'den 1600'e yükseltildi
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
        "    min-width: 800px;"  // Minimum genişlik eklendi
        "}"
    );
    
    // Detaylı scroll area'ya da normal scroll area ile aynı boyut politikalarını uygula
    detailedResultScrollArea->setMinimumHeight(500);
    detailedResultScrollArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    
    QWidget *detailedResultContainer = new QWidget(detailedResultScrollArea);
    QVBoxLayout *detailedResultContainerLayout = new QVBoxLayout(detailedResultContainer);
    detailedResultContainerLayout->setContentsMargins(10, 15, 10, 15); // İçerik kenar boşlukları artırıldı
    
    detailedResultTextEdit = new QPlainTextEdit();
    detailedResultTextEdit->setReadOnly(true);
    setupTextEditStyle(detailedResultTextEdit);
    detailedResultTextEdit->setMinimumHeight(1600); // 800'den 1600'e yükseltildi
    detailedResultContainerLayout->addWidget(detailedResultTextEdit);
    
    detailedResultScrollArea->setWidget(detailedResultContainer);
    detailedResultScrollArea->setVisible(false);
    resultsLayout->addWidget(detailedResultScrollArea);
    
    // API log widget - Yükseklik artırıldı
    QGroupBox *apiGroup = new QGroupBox(tr("API İletişimi"), this);
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
    setupTextEditStyle(apiLogTextEdit);
    apiLogTextEdit->setMinimumHeight(50); // 100'den 50'ye düşürüldü (daha da küçüldü)
    apiLayout->addWidget(apiLogTextEdit);
    
    // Bu widget'lar başlangıçta gizli kalacak ve gerektiğinde gösterilecek
    resultsWidget->setVisible(false);
    apiGroup->setVisible(false);
    
    contentAreaLayout->addWidget(resultsWidget);
    contentAreaLayout->addWidget(apiGroup);

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
        
        // CDR işlemini başlat (şu an için sadece bilgi mesajı göster)
        QMessageBox::information(this, tr("CDR"), tr("Content Disarm and Reconstruction taraması henüz hazır değil."));
    });
    
    // Sandbox butonu için bağlantı
    connect(sandboxBtn, &QPushButton::clicked, [this, resultsWidget, apiGroup, detailedResultScrollArea, resultScrollArea]() {
        resultsWidget->setVisible(true);
        apiGroup->setVisible(true);
        detailedResultScrollArea->setVisible(false);
        resultScrollArea->setVisible(true);
        
        // Sandbox analiz işlemini başlat (şu an için sadece bilgi mesajı göster)
        QMessageBox::information(this, tr("Sandbox"), tr("Sandbox analiz işlemi henüz hazır değil."));
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
    // Checking if response is empty or invalid
    if (response.isEmpty()) {
        resultTextEdit->clear();
        resultTextEdit->appendPlainText("❌ Hata: API yanıtı boş veya geçersiz.");
        apiLogTextEdit->appendPlainText(QString("\n📥 Alınan Yanıt [%1]: Boş veya geçersiz yanıt")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
        return;
    }
    
    // Normal görünüm için basit sonuçlar
    resultTextEdit->clear();
    
    try {
        showNormalResults(response);
        
        // Also populate the detailed view but keep it hidden until requested
        detailedResultTextEdit->clear();
        showDetailedResults(response);
        
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

void MainWindow::showNormalResults(const QJsonObject& response) {
    // Null kontrol
    if (response.isEmpty()) {
        resultTextEdit->appendPlainText("❌ API yanıtı boş veya geçersiz.");
        return;
    }

    // Data nesnesini kontrol et
    if (!response.contains("data") || response["data"].isNull()) {
        resultTextEdit->appendPlainText("❌ Üzgünüz, dosya tarama sonuçları alınamadı.");
        return;
    }

    QJsonObject data = response["data"].toObject();
    
    // Attributes nesnesini kontrol et
    if (!data.contains("attributes") || data["attributes"].isNull()) {
        resultTextEdit->appendPlainText("❌ Dosya analiz sonuçları bulunamadı.");
        return;
    }

    QJsonObject attributes = data["attributes"].toObject();
    
    // Başlık
    resultTextEdit->appendPlainText("=== Dosya Güvenlik Raporu ===\n");
    
    // Genel Değerlendirme - Güvenli kontrol
    if (attributes.contains("stats") && !attributes["stats"].isNull()) {
        QJsonObject stats = attributes["stats"].toObject();
        int malicious = stats.contains("malicious") ? stats["malicious"].toInt() : 0;
        int suspicious = stats.contains("suspicious") ? stats["suspicious"].toInt() : 0;
        
        // Güvenlik durumu
        if (malicious > 0) {
            resultTextEdit->appendPlainText("⛔ TEHLİKE DURUMU");
            resultTextEdit->appendPlainText("------------------");
            resultTextEdit->appendPlainText("Bu dosya zararlı yazılım içerebilir!");
            resultTextEdit->appendPlainText(QString("🔴 %1 antivirüs programı bu dosyayı zararlı olarak tespit etti.").arg(malicious));
        } else if (suspicious > 0) {
            resultTextEdit->appendPlainText("⚠️ DİKKAT");
            resultTextEdit->appendPlainText("------------------");
            resultTextEdit->appendPlainText("Bu dosya şüpheli davranışlar gösteriyor.");
            resultTextEdit->appendPlainText(QString("🟡 %1 antivirüs programı bu dosyayı şüpheli buluyor.").arg(suspicious));
        } else {
            resultTextEdit->appendPlainText("✅ GÜVENLİ");
            resultTextEdit->appendPlainText("------------------");
            resultTextEdit->appendPlainText("Bu dosyada herhangi bir tehdit tespit edilmedi.");
        }
        resultTextEdit->appendPlainText("");
    }

    // Dosya Bilgileri
    resultTextEdit->appendPlainText("\n📄 DOSYA BİLGİLERİ");
    resultTextEdit->appendPlainText("------------------");
    if (attributes.contains("meaningful_name") && !attributes["meaningful_name"].isNull()) {
        resultTextEdit->appendPlainText(QString("📝 Dosya Adı: %1").arg(attributes["meaningful_name"].toString()));
    }
    if (attributes.contains("type_description") && !attributes["type_description"].isNull()) {
        resultTextEdit->appendPlainText(QString("📁 Dosya Türü: %1").arg(attributes["type_description"].toString()));
    }
    if (attributes.contains("size") && !attributes["size"].isNull()) {
        double sizeInMB = attributes["size"].toDouble() / (1024 * 1024);
        resultTextEdit->appendPlainText(QString("💾 Boyut: %1 MB").arg(sizeInMB, 0, 'f', 2));
    }

    // Topluluk Değerlendirmesi
    if (attributes.contains("total_votes") && !attributes["total_votes"].isNull()) {
        QJsonObject votes = attributes["total_votes"].toObject();
        int harmlessVotes = votes.contains("harmless") ? votes["harmless"].toInt() : 0;
        int maliciousVotes = votes.contains("malicious") ? votes["malicious"].toInt() : 0;
        
        if (harmlessVotes > 0 || maliciousVotes > 0) {
            resultTextEdit->appendPlainText("\n👥 TOPLULUK YORUMLARI");
            resultTextEdit->appendPlainText("------------------");
            resultTextEdit->appendPlainText(QString("👍 %1 kullanıcı bu dosyanın güvenli olduğunu düşünüyor").arg(harmlessVotes));
            resultTextEdit->appendPlainText(QString("👎 %1 kullanıcı bu dosyanın zararlı olduğunu düşünüyor").arg(maliciousVotes));
        }
    }

    // Öneriler
    resultTextEdit->appendPlainText("\n💡 ÖNERİLER");
    resultTextEdit->appendPlainText("------------------");
    if (attributes.contains("stats") && !attributes["stats"].isNull()) {
        QJsonObject stats = attributes["stats"].toObject();
        int malicious = stats.contains("malicious") ? stats["malicious"].toInt() : 0;
        int suspicious = stats.contains("suspicious") ? stats["suspicious"].toInt() : 0;
        
        if (malicious > 0) {
            resultTextEdit->appendPlainText("❗ Bu dosyayı çalıştırmanız önerilmez!");
            resultTextEdit->appendPlainText("❗ Dosyayı hemen silin veya karantinaya alın.");
            resultTextEdit->appendPlainText("❗ Sisteminizi tam taramadan geçirin.");
        } else if (suspicious > 0) {
            resultTextEdit->appendPlainText("⚠️ Bu dosyayı güvenilir bir kaynaktan aldıysanız kullanabilirsiniz.");
            resultTextEdit->appendPlainText("⚠️ Emin değilseniz, dosyayı çalıştırmadan önce bir güvenlik uzmanına danışın.");
        } else {
            resultTextEdit->appendPlainText("✅ Bu dosyayı güvenle kullanabilirsiniz.");
            resultTextEdit->appendPlainText("💡 Yine de her zaman güncel bir antivirüs kullanmanızı öneririz.");
        }
    }
}

void MainWindow::showDetailedResults(const QJsonObject& response) {
    // Null kontrol
    if (response.isEmpty()) {
        detailedResultTextEdit->appendPlainText("❌ API yanıtı boş veya geçersiz.");
        return;
    }

    // Data nesnesini kontrol et
    if (!response.contains("data") || response["data"].isNull()) {
        detailedResultTextEdit->appendPlainText("❌ Detaylı analiz sonuçları alınamadı.");
        return;
    }

    QJsonObject data = response["data"].toObject();
    
    // Attributes nesnesini kontrol et
    if (!data.contains("attributes") || data["attributes"].isNull()) {
        detailedResultTextEdit->appendPlainText("❌ Dosya özellikleri bulunamadı.");
        return;
    }

    QJsonObject attributes = data["attributes"].toObject();
    
    // Başlık
    detailedResultTextEdit->appendPlainText("████████████████████████████████████████████████████████████");
    detailedResultTextEdit->appendPlainText("█            𝐃 𝐄 𝐓 𝐀 𝐘 𝐋 𝐈   𝐀 𝐍 𝐀 𝐋 İ 𝐙            █");
    detailedResultTextEdit->appendPlainText("████████████████████████████████████████████████████████████\n");
    
    // İstatistikler
    if (attributes.contains("stats") && !attributes["stats"].isNull()) {
        QJsonObject stats = attributes["stats"].toObject();
        detailedResultTextEdit->appendPlainText("📊 TARAMA İSTATİSTİKLERİ");
        detailedResultTextEdit->appendPlainText("════════════════════════");
        detailedResultTextEdit->appendPlainText(QString("📌 Toplam Tarama: %1").arg(stats.contains("total") ? stats["total"].toInt() : 0));
        detailedResultTextEdit->appendPlainText(QString("🔴 Zararlı: %1").arg(stats.contains("malicious") ? stats["malicious"].toInt() : 0));
        detailedResultTextEdit->appendPlainText(QString("🟡 Şüpheli: %1").arg(stats.contains("suspicious") ? stats["suspicious"].toInt() : 0));
        detailedResultTextEdit->appendPlainText(QString("🟢 Temiz: %1").arg(stats.contains("harmless") ? stats["harmless"].toInt() : 0));
        detailedResultTextEdit->appendPlainText(QString("⚪ Analiz Edilemedi: %1\n").arg(stats.contains("undetected") ? stats["undetected"].toInt() : 0));
    }

    // Detaylı Dosya Bilgileri
    detailedResultTextEdit->appendPlainText("\n📄 DETAYLI DOSYA BİLGİLERİ");
    detailedResultTextEdit->appendPlainText("════════════════════════");
    if (attributes.contains("meaningful_name") && !attributes["meaningful_name"].isNull()) {
        detailedResultTextEdit->appendPlainText(QString("📝 Dosya Adı: %1").arg(attributes["meaningful_name"].toString()));
    }
    if (attributes.contains("type_description") && !attributes["type_description"].isNull()) {
        detailedResultTextEdit->appendPlainText(QString("📁 Dosya Türü: %1").arg(attributes["type_description"].toString()));
    }
    if (attributes.contains("size") && !attributes["size"].isNull()) {
        double sizeInMB = attributes["size"].toDouble() / (1024 * 1024);
        detailedResultTextEdit->appendPlainText(QString("💾 Boyut: %.2f MB").arg(sizeInMB));
    }
    if (attributes.contains("md5") && !attributes["md5"].isNull()) {
        detailedResultTextEdit->appendPlainText(QString("🔑 MD5: %1").arg(attributes["md5"].toString()));
    }
    if (attributes.contains("sha1") && !attributes["sha1"].isNull()) {
        detailedResultTextEdit->appendPlainText(QString("🔑 SHA1: %1").arg(attributes["sha1"].toString()));
    }
    if (attributes.contains("sha256") && !attributes["sha256"].isNull()) {
        detailedResultTextEdit->appendPlainText(QString("🔑 SHA256: %1").arg(attributes["sha256"].toString()));
    }
    if (attributes.contains("first_submission_date") && !attributes["first_submission_date"].isNull()) {
        QDateTime firstSeen = QDateTime::fromSecsSinceEpoch(attributes["first_submission_date"].toInt());
        if (firstSeen.isValid()) {
            detailedResultTextEdit->appendPlainText(QString("🕒 İlk Görülme: %1").arg(firstSeen.toString("dd.MM.yyyy hh:mm")));
        }
    }
    if (attributes.contains("last_analysis_date") && !attributes["last_analysis_date"].isNull()) {
        QDateTime lastAnalysis = QDateTime::fromSecsSinceEpoch(attributes["last_analysis_date"].toInt());
        if (lastAnalysis.isValid()) {
            detailedResultTextEdit->appendPlainText(QString("🕒 Son Analiz: %1").arg(lastAnalysis.toString("dd.MM.yyyy hh:mm")));
        }
    }
    
    // Eğer mevcutsa dosya tipi detayları
    if (attributes.contains("trid") && attributes["trid"].isArray()) {
        detailedResultTextEdit->appendPlainText("\n📋 DOSYA TİPİ DETAYLARI");
        detailedResultTextEdit->appendPlainText("════════════════════════");
        QJsonArray tridArray = attributes["trid"].toArray();
        for (const QJsonValue &tridValue : tridArray) {
            if (!tridValue.isObject()) continue;
            
            QJsonObject tridObj = tridValue.toObject();
            if (tridObj.contains("file_type") && tridObj.contains("probability")) {
                detailedResultTextEdit->appendPlainText(QString("  • %1 (%2%)")
                    .arg(tridObj["file_type"].toString())
                    .arg(tridObj["probability"].toDouble()));
            }
        }
    }
    
    // İmza bilgileri 
    if (attributes.contains("signature_info") && !attributes["signature_info"].isNull()) {
        detailedResultTextEdit->appendPlainText("\n🔏 İMZA BİLGİLERİ");
        detailedResultTextEdit->appendPlainText("════════════════════════");
        QJsonObject signInfo = attributes["signature_info"].toObject();
        
        if (signInfo.contains("product") && !signInfo["product"].isNull()) {
            detailedResultTextEdit->appendPlainText(QString("📦 Ürün: %1").arg(signInfo["product"].toString()));
        }
        if (signInfo.contains("copyright") && !signInfo["copyright"].isNull()) {
            detailedResultTextEdit->appendPlainText(QString("©️ Telif Hakkı: %1").arg(signInfo["copyright"].toString()));
        }
        if (signInfo.contains("description") && !signInfo["description"].isNull()) {
            detailedResultTextEdit->appendPlainText(QString("📝 Açıklama: %1").arg(signInfo["description"].toString()));
        }
        if (signInfo.contains("file_version") && !signInfo["file_version"].isNull()) {
            detailedResultTextEdit->appendPlainText(QString("🔢 Dosya Versiyonu: %1").arg(signInfo["file_version"].toString()));
        }
        if (signInfo.contains("internal_name") && !signInfo["internal_name"].isNull()) {
            detailedResultTextEdit->appendPlainText(QString("🏷️ Dahili İsim: %1").arg(signInfo["internal_name"].toString()));
        }
        if (signInfo.contains("original_name") && !signInfo["original_name"].isNull()) {
            detailedResultTextEdit->appendPlainText(QString("📄 Orijinal İsim: %1").arg(signInfo["original_name"].toString()));
        }
        
        // İmza durumu
        if (signInfo.contains("verified") && !signInfo["verified"].isNull()) {
            bool isVerified = signInfo["verified"].toBool();
            if (isVerified) {
                detailedResultTextEdit->appendPlainText("✅ İmza Doğrulandı");
            } else {
                detailedResultTextEdit->appendPlainText("❌ İmza Doğrulamadı");
            }
        }
        
        // İmzalayan
        if (signInfo.contains("signers") && signInfo["signers"].isArray()) {
            QJsonArray signers = signInfo["signers"].toArray();
            if (!signers.isEmpty()) {
                detailedResultTextEdit->appendPlainText("\n📝 İmzalayanlar:");
                for (const QJsonValue &signer : signers) {
                    if (!signer.isString()) continue;
                    detailedResultTextEdit->appendPlainText(QString("  • %1").arg(signer.toString()));
                }
            }
        }
    }

    // Davranış Analizi
    if (attributes.contains("sandbox_verdicts") && !attributes["sandbox_verdicts"].isNull()) {
        detailedResultTextEdit->appendPlainText("\n🧪 SANDBOX ANALİZ SONUÇLARI");
        detailedResultTextEdit->appendPlainText("════════════════════════");
        QJsonObject sandboxResults = attributes["sandbox_verdicts"].toObject();
        
        for (auto it = sandboxResults.begin(); it != sandboxResults.end(); ++it) {
            if (!it.value().isObject()) continue;
            
            QJsonObject verdict = it.value().toObject();
            QString category = verdict.contains("category") ? verdict["category"].toString() : "";
            QString explanation = verdict.contains("explanation") ? verdict["explanation"].toString() : "";
            
            QString status;
            if (category == "malicious") {
                status = "⛔ Zararlı";
            } else if (category == "suspicious") {
                status = "⚠️ Şüpheli";
            } else {
                status = "✅ Güvenli";
            }
            
            detailedResultTextEdit->appendPlainText(QString("\n▶️ Test Ortamı: %1").arg(it.key()));
            detailedResultTextEdit->appendPlainText(QString("   Sonuç: %1").arg(status));
            if (!explanation.isEmpty()) {
                detailedResultTextEdit->appendPlainText(QString("   📝 Açıklama: %1").arg(explanation));
            }
        }
    }

    // Davranış Detayları
    if (attributes.contains("sandbox_verdicts") && !attributes["sandbox_verdicts"].isNull()) {
        QJsonObject sandboxVerdicts = attributes["sandbox_verdicts"].toObject();
        
        // Her sandbox için ayrı davranış analizi
        for (auto sandboxIt = sandboxVerdicts.begin(); sandboxIt != sandboxVerdicts.end(); ++sandboxIt) {
            if (!sandboxIt.value().isObject()) continue;
            
            QString sandboxName = sandboxIt.key();
            QJsonObject sandbox = sandboxIt.value().toObject();
            
            if (sandbox.contains("malware_classification") && sandbox["malware_classification"].isObject()) {
                detailedResultTextEdit->appendPlainText(QString("\n🔬 %1 SANDBOX ANALİZİ").arg(sandboxName.toUpper()));
                detailedResultTextEdit->appendPlainText("════════════════════════");
                
                QJsonObject classification = sandbox["malware_classification"].toObject();
                
                //
                if (classification.contains("detected_behaviors") && classification["detected_behaviors"].isArray()) {
                    QJsonArray behaviors = classification["detected_behaviors"].toArray();
                    if (!behaviors.isEmpty()) {
                        detailedResultTextEdit->appendPlainText("\n   🔍 Tespit Edilen Davranışlar:");
                        for (const QJsonValue &behavior : behaviors) {
                            if (!behavior.isString()) continue;
                            detailedResultTextEdit->appendPlainText(QString("   • %1").arg(behavior.toString()));
                        }
                    }
                }
                
                // Taktik ve teknikler (MITRE ATT&CK)
                if (classification.contains("tactics_and_techniques") && classification["tactics_and_techniques"].isArray()) {
                    QJsonArray tactics = classification["tactics_and_techniques"].toArray();
                    if (!tactics.isEmpty()) {
                        detailedResultTextEdit->appendPlainText("\n   🎯 MITRE ATT&CK Taktikleri:");
                        for (const QJsonValue &tacticValue : tactics) {
                            if (!tacticValue.isObject()) continue;
                            
                            QJsonObject tactic = tacticValue.toObject();
                            if (tactic.contains("tactic") && tactic.contains("id")) {
                                detailedResultTextEdit->appendPlainText(QString("   • %1 (%2)")
                                    .arg(tactic["tactic"].toString())
                                    .arg(tactic["id"].toString()));
                                
                                if (tactic.contains("techniques") && tactic["techniques"].isArray()) {
                                    QJsonArray techniques = tactic["techniques"].toArray();
                                    for (const QJsonValue &techValue : techniques) {
                                        if (!techValue.isObject()) continue;
                                        
                                        QJsonObject tech = techValue.toObject();
                                        if (tech.contains("technique") && tech.contains("id")) {
                                            detailedResultTextEdit->appendPlainText(QString("     - %1 (%2)")
                                                .arg(tech["technique"].toString())
                                                .arg(tech["id"].toString()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Yürütülebilir dosya detayları
    if (attributes.contains("pe_info") && !attributes["pe_info"].isNull()) {
        detailedResultTextEdit->appendPlainText("\n💻 ÇALIŞTIRILEBILIR DOSYA DETAYLARI");
        detailedResultTextEdit->appendPlainText("════════════════════════");
        QJsonObject peInfo = attributes["pe_info"].toObject();
        
        if (peInfo.contains("entry_point") && !peInfo["entry_point"].isNull()) {
            detailedResultTextEdit->appendPlainText(QString("🚀 Giriş Noktası: 0x%1")
                .arg(QString::number(peInfo["entry_point"].toInt(), 16).toUpper()));
        }
        
        if (peInfo.contains("imphash") && !peInfo["imphash"].isNull()) {
            detailedResultTextEdit->appendPlainText(QString("🔑 Import Hash: %1").arg(peInfo["imphash"].toString()));
        }
        
        if (peInfo.contains("sections") && peInfo["sections"].isArray()) {
            QJsonArray sections = peInfo["sections"].toArray();
            if (!sections.isEmpty()) {
                detailedResultTextEdit->appendPlainText("\n   📊 Bölümler:");
                detailedResultTextEdit->appendPlainText("   ════════════════════════");
                for (const QJsonValue &sectionValue : sections) {
                    if (!sectionValue.isObject()) continue;
                    
                    QJsonObject section = sectionValue.toObject();
                    if (section.contains("name") && section.contains("size") && section.contains("entropy")) {
                        detailedResultTextEdit->appendPlainText(QString("   • %1 (Boyut: %2 bayt, Entropy: %3)")
                            .arg(section["name"].toString())
                            .arg(section["size"].toInt())
                            .arg(section["entropy"].toDouble(), 0, 'f', 2));
                    }
                }
            }
        }
        
        if (peInfo.contains("imports") && peInfo["imports"].isObject()) {
            QJsonObject imports = peInfo["imports"].toObject();
            if (!imports.isEmpty()) {
                detailedResultTextEdit->appendPlainText("\n   📚 İçe Aktarılan DLL Dosyaları:");
                detailedResultTextEdit->appendPlainText("   ════════════════════════");
                int count = 0;
                for (auto libIt = imports.begin(); libIt != imports.end(); ++libIt) {
                    if (++count > 5) { // Sınırla
                        detailedResultTextEdit->appendPlainText("   ... ve diğer DLL'ler");
                        break;
                    }
                    QString lib = libIt.key();
                    detailedResultTextEdit->appendPlainText(QString("   • %1").arg(lib));
                    
                    if (!libIt.value().isArray()) continue;
                    QJsonArray functions = libIt.value().toArray();
                    
                    int funcCount = 0;
                    for (const QJsonValue &funcValue : functions) {
                        if (++funcCount > 3) { // Her DLL için sadece birkaç fonksiyon göster
                            detailedResultTextEdit->appendPlainText("     ... ve diğer fonksiyonlar");
                            break;
                        }
                        if (!funcValue.isString()) continue;
                        detailedResultTextEdit->appendPlainText(QString("     - %1").arg(funcValue.toString()));
                    }
                }
            }
        }
    }

    // Davranış analizi
    if (attributes.contains("behavior") && !attributes["behavior"].isNull()) {
        QJsonObject behavior = attributes["behavior"].toObject();
        detailedResultTextEdit->appendPlainText("\n🔄 DAVRANIŞSAL ANALİZ");
        detailedResultTextEdit->appendPlainText("════════════════════════");
        
        // Process Tree - Süreç Ağacı
        if (behavior.contains("processes") && behavior["processes"].isArray()) {
            QJsonArray processes = behavior["processes"].toArray();
            if (!processes.isEmpty()) {
                detailedResultTextEdit->appendPlainText("\n   🌳 Süreç Ağacı:");
                
                for (const QJsonValue &processValue : processes) {
                    if (!processValue.isObject()) continue;
                    
                    QJsonObject process = processValue.toObject();
                    if (process.contains("name") && process.contains("pid") && process.contains("command_line")) {
                        QString name = process["name"].toString();
                        QString pid = QString::number(process["pid"].toInt());
                        QString cmd = process["command_line"].toString();
                        
                        detailedResultTextEdit->appendPlainText(QString("   • %1 (PID: %2)").arg(name, pid));
                        detailedResultTextEdit->appendPlainText(QString("     Komut: %1").arg(cmd));
                    }
                }
            }
        }
        
        // Network aktivitesi
        if (behavior.contains("network_activity")) {
            QJsonValue networkValue = behavior["network_activity"];
            if (networkValue.isArray()) {
                QJsonArray networkActivity = networkValue.toArray();
                if (!networkActivity.isEmpty()) {
                    detailedResultTextEdit->appendPlainText("\n   🌐 Ağ Aktivitesi:");
                    for (const QJsonValue &activity : networkActivity) {
                        if (!activity.isString()) continue;
                        detailedResultTextEdit->appendPlainText(QString("   • %1").arg(activity.toString()));
                    }
                }
            }
        }
        
        // Dosya sistemi aktivitesi
        if (behavior.contains("filesystem_activity")) {
            QJsonValue fsValue = behavior["filesystem_activity"];
            if (fsValue.isArray()) {
                QJsonArray fsActivity = fsValue.toArray();
                if (!fsActivity.isEmpty()) {
                    detailedResultTextEdit->appendPlainText("\n   💽 Dosya Sistemi Aktivitesi:");
                    for (const QJsonValue &activity : fsActivity) {
                        if (!activity.isString()) continue;
                        detailedResultTextEdit->appendPlainText(QString("   • %1").arg(activity.toString()));
                    }
                }
            }
        }
        
        // Registry aktivitesi
        if (behavior.contains("registry_activity")) {
            QJsonValue regValue = behavior["registry_activity"];
            if (regValue.isArray()) {
                QJsonArray regActivity = regValue.toArray();
                if (!regActivity.isEmpty()) {
                    detailedResultTextEdit->appendPlainText("\n   🔧 Registry Aktivitesi:");
                    for (const QJsonValue &activity : regActivity) {
                        if (!activity.isString()) continue;
                        detailedResultTextEdit->appendPlainText(QString("   • %1").arg(activity.toString()));
                    }
                }
            }
        }
    }

    // Detaylı Antivirüs Sonuçları
    if (attributes.contains("last_analysis_results") && !attributes["last_analysis_results"].isNull()) {
        detailedResultTextEdit->appendPlainText("\n🛡️ DETAYLI ANTİVİRÜS SONUÇLARI");
        detailedResultTextEdit->appendPlainText("════════════════════════");
        QJsonObject results = attributes["last_analysis_results"].toObject();
        
        QStringList malicious, suspicious, clean;
        
        for (auto it = results.begin(); it != results.end(); ++it) {
            if (!it.value().isObject()) continue;
            
            QString engine = it.key();
            QJsonObject result = it.value().toObject();
            
            QString category = result.contains("category") ? result["category"].toString() : "";
            QString resultStr = result.contains("result") ? result["result"].toString() : "";
            QString version = result.contains("engine_version") ? result["engine_version"].toString() : "";
            QString update = result.contains("engine_update") ? result["engine_update"].toString() : "";
            
            QString entry = QString("%1 %2 %3: %4")
                .arg(engine)
                .arg(!version.isEmpty() ? QString("(v%1)").arg(version) : "")
                .arg(!update.isEmpty() ? QString("[%1]").arg(update) : "")
                .arg(resultStr.isEmpty() ? "Temiz" : resultStr);
            
            if (category == "malicious") {
                malicious.append(entry);
            } else if (category == "suspicious") {
                suspicious.append(entry);
            } else if (category == "harmless" || category == "undetected") {
                clean.append(entry);
            }
        }
        
        // Zararlı tespitleri
        if (!malicious.isEmpty()) {
            detailedResultTextEdit->appendPlainText("\n🔴 Zararlı Tespiti Yapan Antivirüsler:");
            for (const QString& entry : malicious) {
                detailedResultTextEdit->appendPlainText("  ▪️ " + entry);
            }
        }
        
        // Şüpheli tespitler
        if (!suspicious.isEmpty()) {
            detailedResultTextEdit->appendPlainText("\n🟡 Şüpheli Tespit Yapan Antivirüsler:");
            for (const QString& entry : suspicious) {
                detailedResultTextEdit->appendPlainText("  ▫️ " + entry);
            }
        }
        
        // Temiz sonuçlar (sadece 15 tanesini göster)
        if (!clean.isEmpty()) {
            detailedResultTextEdit->appendPlainText("\n🟢 Temiz Sonuç Veren Antivirüsler:");
            int maxClean = qMin(15, clean.size());
            for (int i = 0; i < maxClean; ++i) {
                detailedResultTextEdit->appendPlainText("  ✓ " + clean[i]);
            }
            if (clean.size() > 15) {
                detailedResultTextEdit->appendPlainText(QString("  ... ve %1 antivirüs daha").arg(clean.size() - 15));
            }
        }
    }

    // Topluluk Değerlendirmesi
    if (attributes.contains("total_votes") && !attributes["total_votes"].isNull()) {
        QJsonObject votes = attributes["total_votes"].toObject();
        int harmlessVotes = votes.contains("harmless") ? votes["harmless"].toInt() : 0;
        int maliciousVotes = votes.contains("malicious") ? votes["malicious"].toInt() : 0;
        
        if (harmlessVotes > 0 || maliciousVotes > 0) {
            detailedResultTextEdit->appendPlainText("\n👥 TOPLULUK DEĞERLENDİRMESİ");
            detailedResultTextEdit->appendPlainText("════════════════════════");
            detailedResultTextEdit->appendPlainText(QString("👍 Güvenli Oylar: %1").arg(harmlessVotes));
            detailedResultTextEdit->appendPlainText(QString("👎 Zararlı Oylar: %1").arg(maliciousVotes));
            
            // Oy oranı hesapla
            if (harmlessVotes + maliciousVotes > 0) {
                double totalVotes = harmlessVotes + maliciousVotes;
                double harmlessPercentage = (harmlessVotes / totalVotes) * 100;
                double maliciousPercentage = (maliciousVotes / totalVotes) * 100;
                
                // Görsel bar gösterimi
                QString harmlessBar = "";
                QString maliciousBar = "";
                
                int barLength = 30; // Toplam bar uzunluğu
                int harmlessBarLen = qRound((harmlessVotes / totalVotes) * barLength);
                int maliciousBarLen = barLength - harmlessBarLen;
                
                for (int i = 0; i < harmlessBarLen; ++i) harmlessBar += "█";
                for (int i = 0; i < maliciousBarLen; ++i) maliciousBar += "█";
                
                detailedResultTextEdit->appendPlainText(QString("\n🟢 %1 | %2% Güvenli")
                    .arg(harmlessBar).arg(harmlessPercentage, 0, 'f', 1));
                detailedResultTextEdit->appendPlainText(QString("🔴 %1 | %2% Zararlı")
                    .arg(maliciousBar).arg(maliciousPercentage, 0, 'f', 1));
            }
        }
    }
    
    // Analiz Özeti
    detailedResultTextEdit->appendPlainText("\n📋 ANALİZ ÖZETİ");
    detailedResultTextEdit->appendPlainText("════════════════════════");
    if (attributes.contains("stats") && !attributes["stats"].isNull()) {
        QJsonObject stats = attributes["stats"].toObject();
        int malicious = stats.contains("malicious") ? stats["malicious"].toInt() : 0;
        int suspicious = stats.contains("suspicious") ? stats["suspicious"].toInt() : 0;
        int total = stats.contains("total") ? stats["total"].toInt() : 0;
        
        if (total > 0) {
            if (malicious > 0) {
                double maliciousPercentage = (double)malicious / total * 100;
                detailedResultTextEdit->appendPlainText(QString("⛔ SONUÇ: ZARARLI - Antivirüs motorlarının %1%'i (%2/%3) bu dosyayı zararlı olarak tanımladı.")
                    .arg(maliciousPercentage, 0, 'f', 1).arg(malicious).arg(total));
                detailedResultTextEdit->appendPlainText("\n⚠️ TAVSİYE: Bu dosya potansiyel olarak tehlikelidir ve güvenlik riskleri içerebilir.");
                detailedResultTextEdit->appendPlainText("            Dosyayı çalıştırmaktan kaçınmanız ve sistemden kaldırmanız önerilir.");
            } else if (suspicious > 0) {
                double suspiciousPercentage = (double)suspicious / total * 100;
                detailedResultTextEdit->appendPlainText(QString("⚠️ SONUÇ: ŞÜPHELİ - Antivirüs motorlarının %1%'i (%2/%3) bu dosyayı şüpheli olarak tanımladı.")
                    .arg(suspiciousPercentage, 0, 'f', 1).arg(suspicious).arg(total));
                detailedResultTextEdit->appendPlainText("\n⚠️ TAVSİYE: Bu dosya potansiyel olarak riskli olabilir. Güvenilir bir kaynaktan geldiğinden emin değilseniz");
                detailedResultTextEdit->appendPlainText("            dikkatli olmanız ve dosyayı çalıştırmamanız önerilir.");
            } else {
                detailedResultTextEdit->appendPlainText("✅ SONUÇ: GÜVENLİ - Bu dosya hiçbir antivirüs tarafından zararlı veya şüpheli olarak tespit edilmedi.");
                detailedResultTextEdit->appendPlainText("\n💡 TAVSİYE: Bu dosya şu an için güvenli görünüyor. Yine de bilinmeyen kaynaklardan gelen dosyalara");
                detailedResultTextEdit->appendPlainText("            karşı her zaman dikkatli olmanızı ve güncel bir güvenlik yazılımı kullanmanızı öneririz.");
            }
        }
    }
    
    detailedResultTextEdit->appendPlainText("\n████████████████████████████████████████████████████████████");
    detailedResultTextEdit->appendPlainText("█                  𝐑 𝐀 𝐏 𝐎 𝐑  𝐒 𝐎 𝐍 𝐔                  █");
    detailedResultTextEdit->appendPlainText("████████████████████████████████████████████████████████████");
}

void MainWindow::onScanButtonClicked()
{
    try {
        // Dosya seçme
        QString filePath = QFileDialog::getOpenFileName(this, tr("Dosya Seç"), QString(), tr("Tüm Dosyalar (*.*)"));
        if (filePath.isEmpty()) {
            updateStatus(tr("Dosya seçilmedi."));
            return;
        }
        updateStatus(tr("Dosya seçildi. Hash hesaplamaları yapılıyor..."));

        // Hash hesaplamaları
        QString md5Hash    = HashCalculation::Md5Hashing(filePath);
        QString sha1Hash   = HashCalculation::Sha1Hashing(filePath);
        QString sha256Hash = HashCalculation::Sha256Hashing(filePath);

        // Veritabanı aramaları
        QString md5Result    = DbManager::searchHashmMd5(md5Hash);
        QString sha1Result   = DbManager::searchHashSha_1(sha1Hash);
        QString sha256Result = DbManager::searchHashSha_256(sha256Hash);

        // Sonuçları ekranda göstermek için resultTextEdit'i temizleyip yazalım
        if (resultTextEdit) {
            resultTextEdit->clear();
            resultTextEdit->appendPlainText("=== Tarama Sonucu ===");
            resultTextEdit->appendPlainText(QString("MD5: %1 => %2")
                .arg(md5Hash, md5Result.isEmpty() ? "Temiz" : md5Result));
            resultTextEdit->appendPlainText(QString("SHA1: %1 => %2")
                .arg(sha1Hash, sha1Result.isEmpty() ? "Temiz" : sha1Result));
            resultTextEdit->appendPlainText(QString("SHA256: %1 => %2")
                .arg(sha256Hash, sha256Result.isEmpty() ? "Temiz" : sha256Result));

            // Eğer hiçbir hash veritabanında yoksa dosya temiz
            if (md5Result.isEmpty() && sha1Result.isEmpty() && sha256Result.isEmpty()) {
                resultTextEdit->appendPlainText("\nTehdit algılanmadı. Dosya temiz.");
            }

            // --- Dinamik YARA Tarama Adımı ---
            resultTextEdit->appendPlainText("\n--- Dinamik YARA Tarama Başlatılıyor ---");
            updateStatus(tr("YARA kuralları yükleniyor..."));
            std::string yaraRulePath = "Rules/test.yar"; // Test kural dosyası
            
            if (!yaraManager) {
                resultTextEdit->appendPlainText("YARA yöneticisi oluşturulmamış");
                updateStatus(tr("YARA yöneticisi hatası"));
                return;
            }
            
            std::error_code yaraErr = yaraManager->loadRules(yaraRulePath);
            if (yaraErr) {
                resultTextEdit->appendPlainText(QString("YARA kural dosyası yüklenemedi: %1").arg(QString::fromStdString(yaraErr.message())));
                updateStatus(tr("YARA kuralı yüklenemedi"));
                return;
            }
            
            resultTextEdit->appendPlainText("YARA kuralları başarıyla yüklendi. Dosya taranıyor...");
            updateStatus(tr("YARA ile dosya taranıyor..."));
            std::vector<std::string> yaraMatches;
            std::error_code scanErr = yaraManager->scanFile(filePath.toStdString(), yaraMatches);
            if (scanErr) {
                resultTextEdit->appendPlainText(QString("YARA tarama hatası: %1").arg(QString::fromStdString(scanErr.message())));
                updateStatus(tr("YARA tarama hatası"));
                return;
            }
            if (yaraMatches.empty()) {
                resultTextEdit->appendPlainText("YARA: Herhangi bir tehdit tespit edilmedi.");
            } else {
                resultTextEdit->appendPlainText("YARA: Tehdit tespit edildi!");
                for (const auto& match : yaraMatches) {
                    resultTextEdit->appendPlainText(QString("- %1").arg(QString::fromStdString(match)));
                }
            }
            updateStatus(tr("Tarama tamamlandı."));
        } else {
            QMessageBox::critical(this, tr("Hata"), tr("Sonuç gösterme bileşeni oluşturulmamış"));
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Hata"), QString(tr("Tarama sırasında bir hata oluştu: %1")).arg(e.what()));
    } catch (...) {
        QMessageBox::critical(this, tr("Hata"), tr("Tarama sırasında bilinmeyen bir hata oluştu"));
    }
}

void MainWindow::onsendVirusTotalButtonClicked() {
    if (!apiManager->hasApiKey()) {
        QMessageBox::warning(this, "Uyarı", "Lütfen önce API key ayarlayın");
        showApiKeyDialog(); // API key eklemesi için hemen dialog göster
        if (!apiManager->hasApiKey()) { // Kullanıcı iptal ettiyse çık
            return;
        }
    }

    // Dosya seçme
    QString filePath = QFileDialog::getOpenFileName(this, tr("Dosya Seç"), QString(), tr("Tüm Dosyalar (*.*)"));
    if (filePath.isEmpty()) {
        updateStatus("Dosya seçilmedi");
        return;
    }

    updateStatus("Dosya seçildi. Hash hesaplanıyor...");

    // Hash hesaplamaları - try/catch bloğu ile güvenli hale getirildi
    try {
        // VirusTotal API için SHA-256 hash'ini hesapla
        QString sha256Hash = HashCalculation::Sha256Hashing(filePath);
        if (sha256Hash.isEmpty()) {
            updateStatus("Hash hesaplanamadı, dosya okunamıyor olabilir");
            return;
        }

        updateStatus("VirusTotal'e sorgu gönderiliyor...");
        
        // VirusTotal API isteği gönderilmeden önce UI'ı hazırla
        resultTextEdit->clear();
        resultTextEdit->appendPlainText("VirusTotal sorgusu gönderiliyor...");
        resultTextEdit->appendPlainText(QString("Dosya: %1").arg(QFileInfo(filePath).fileName()));
        resultTextEdit->appendPlainText(QString("SHA-256: %1").arg(sha256Hash));
        resultTextEdit->appendPlainText("\nYanıt bekleniyor...");
        
        // VirusTotal API v3 endpoint'i için doğru formatta istek yap
        apiManager->makeApiRequest(QString("/files/%1").arg(sha256Hash));
    } catch (const std::exception& e) {
        updateStatus(QString("Hata oluştu: %1").arg(e.what()));
        QMessageBox::critical(this, "Hata", QString("İşlem sırasında bir hata oluştu: %1").arg(e.what()));
    } catch (...) {
        updateStatus("Bilinmeyen bir hata oluştu");
        QMessageBox::critical(this, "Hata", "İşlem sırasında bilinmeyen bir hata oluştu");
    }
}

void MainWindow::onApiKeyButtonClicked() {
    showApiKeyDialog();
}

void MainWindow::showApiKeyDialog() {
    ApiKeyDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted) {
        QString apiKey = dialog.getApiKey();
        if (!apiKey.isEmpty()) {
            apiManager->setApiKey(apiKey);
            updateStatus("API key başarıyla ayarlandı");
        }
    }
}

void MainWindow::onApiError(const QString& errorMessage) {
    updateStatus("Hata: " + errorMessage);
    QMessageBox::critical(this, "API Hatası", errorMessage);
}

void MainWindow::updateStatus(const QString& message) {
    try {
        if (statusBar() && statusLabel) {
            statusLabel->setText(message);
            statusBar()->showMessage(message);
        } else {
            // Status label veya statusBar mevcut değilse, sadece statusBar'ı kullan
            if (statusBar()) {
                statusBar()->showMessage(message);
            }
        }
    } catch (const std::exception& e) {
        qWarning() << "Status güncellenirken hata oluştu:" << e.what();
    } catch (...) {
        qWarning() << "Status güncellenirken bilinmeyen hata oluştu";
    }
}

void MainWindow::appendResult(const QString& engine, const QString& result) {
    resultTextEdit->appendPlainText(QString("%1: %2").arg(engine, result));
}

void MainWindow::setupTextEditStyle(QPlainTextEdit* textEdit) {
    textEdit->setStyleSheet(
        "QPlainTextEdit {"
        "    font-family: 'Consolas', 'Menlo', 'Monaco', monospace;"
        "    font-size: 12pt;"
        "    line-height: 1.5;"
        "    padding: 15px;"
        "    padding: 15px;"
        "    background-color: #181818;"
        "    color: #cccccc;"
        "    border: none;"
        "    border-radius: 5px;"
        "    min-width: 600px;"  // Minimum genişlik eklendi
        "}"
        "QScrollBar:vertical {"
        "    background-color: #111111;"
        "    width: 14px;"
        "    margin: 0px;"
        "}"
        "QScrollBar::handle:vertical {"
        "    background-color: #333333;"
        "    min-height: 20px;"
        "    border-radius: 7px;"
        "}"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
        "    height: 0px;"
        "}"
    );
    
    QFont font = textEdit->font();
    font.setPointSize(12);
    textEdit->setFont(font);
}
