#include "../Headers/UserInterface.h"
#include "../Headers/ServiceLocator.h"
#include "../Headers/Dialogs/ApiKeyDialog.h"
#include "../Headers/Dialogs/DockerImageSelectionDialog.h"
#include "../Headers/Dialogs/ServiceStatusDialog.h"
#include "../Headers/Dialogs/HistoryDialog.h"

#include <QMainWindow>
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
#include <QFont>
#include <QIcon>
#include <QDateTime>
#include <QToolButton>
#include <QSplitter>
#include <QFile>
#include <QApplication>
#include <QScreen>
#include <QDebug>
#include <stdexcept>
#include <thread>
#include <chrono>

UserInterface::UserInterface(QWidget *parent)
    : QMainWindow(parent),
      m_statusLabel(nullptr),
      m_progressDialog(nullptr),
      m_currentProgress(0)
{
    // Window ayarları
    setWindowTitle("Endpoint Protection Platform");
    resize(1200, 800);
    
    // Uygulama logosunu ayarla
    setWindowIcon(QIcon(":/images/applogo.png"));
    
    try {
        // Stil dosyasını yükle
        QFile styleFile(":/styles/main.qss");
        if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
            QString styleSheet = QLatin1String(styleFile.readAll());
            this->setStyleSheet(styleSheet);
            styleFile.close();
        } else {
            qWarning() << "Style sheet file could not be opened:" << styleFile.errorString();
        }
        
        // Önce servisleri başlat
        initializeServices();
        
        // Sonra UI elemanlarını oluştur
        initializeUI();
        createActions();
        createMenus();
        createStatusBar();
        
        // İlerleme göstergesini ayarla
        setupProgressDialog();
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Initialization Error"), 
                            tr("An error occurred during application startup: %1").arg(e.what()));
        qCritical() << "Fatal error during initialization:" << e.what();
    } catch (...) {
        QMessageBox::critical(this, tr("Initialization Error"), 
                            tr("An unknown error occurred during application startup."));
        qCritical() << "Unknown fatal error during initialization";
    }
}

UserInterface::~UserInterface()
{
    // Manager sınıfları unique_ptr ve shared_ptr ile yönetildiğinden
    // onların destructor'ları otomatik çağrılacak
    // Diğer cleanup işlemleri burada yapılmalı
}

void UserInterface::setupProgressDialog()
{
    m_progressDialog = new QProgressDialog(tr("Starting operation..."), tr("Cancel"), 0, 100, this);
    m_progressDialog->setWindowModality(Qt::WindowModal);
    m_progressDialog->setAutoClose(true);
    m_progressDialog->setAutoReset(true);
    m_progressDialog->setMinimumDuration(500); // 500 ms'den uzun süren işlemler için göster
    m_progressDialog->reset();
    m_progressDialog->hide();
    m_currentProgress = 0;
}

void UserInterface::initializeServices()
{
    // Smart pointers ile servis nesnelerini oluştur
    // ApiManager singleton'unu al
    m_apiManager = std::shared_ptr<IApiManager>(ApiManager::getInstance());
    
    // Diğer manager'ları oluştur - Factory pattern veya ServiceLocator kullanılabilir
    m_yaraManager = std::shared_ptr<IYaraRuleManager>(ServiceLocator::getYaraRuleManager());
    m_cdrManager = std::shared_ptr<ICdrManager>(ServiceLocator::getCdrManager());
    m_sandboxManager = std::shared_ptr<ISandboxManager>(ServiceLocator::getSandboxManager());
    m_dbManager = std::shared_ptr<IDbManager>(ServiceLocator::getDbManager());
    m_dockerManager = std::shared_ptr<IDockerManager>(ServiceLocator::getDockerManager());
    
    // Null kontrolü - güvenlik için
    if (!m_apiManager || !m_yaraManager || !m_cdrManager || !m_sandboxManager || !m_dbManager || !m_dockerManager) {
        throw std::runtime_error("One or more required services could not be initialized");
    }

    // ScanManager - UI bağımlılığı olan özel sınıf
    m_scanManager = std::make_unique<ScanManager>(
        m_apiManager.get(), 
        m_yaraManager.get(), 
        m_cdrManager.get(), 
        m_sandboxManager.get(), 
        m_dbManager.get(),
        this
    );
    
    // ResultsView - UI bağımlılığı olan bir başka sınıf
    m_resultsView = std::make_unique<ResultsView>(this);
    
    // DockerUIManager
    m_dockerUIManager = std::make_unique<DockerUIManager>(this);
    m_dockerUIManager->setDockerManager(m_dockerManager.get());

    // Docker imaj seçim sinyalini bağla
    connect(m_scanManager.get(), &ScanManager::dockerImageSelectionRequired, 
            this, [this](const QString &serviceType) {
                // İlgili servis türü için mevcut imajları ve seçili imajı al
                QStringList availableImages;
                QString currentImage;
                
                if (serviceType == "CDR") {
                    availableImages = m_scanManager->getAvailableCdrImages();
                    currentImage = m_scanManager->getCurrentCdrImageName();
                } else {
                    availableImages = m_scanManager->getAvailableSandboxImages();
                    currentImage = m_scanManager->getCurrentSandboxImageName();
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
                        m_scanManager->setCdrImageName(selectedImage);
                    } else {
                        m_scanManager->setSandboxImageName(selectedImage);
                    }
                    
                    QMessageBox::information(this, tr("Image Selected"), 
                                          tr("Selected %1 image: %2")
                                          .arg(serviceType)
                                          .arg(selectedImage));
                }
            });

    // İşlem başlangıç/bitiş sinyallerini bağla
    connect(m_scanManager.get(), &ScanManager::operationStarted, this, &UserInterface::handleOperationStarted);
    connect(m_scanManager.get(), &ScanManager::operationCompleted, this, &UserInterface::handleOperationCompleted);
    connect(m_scanManager.get(), &ScanManager::progressUpdated, this, &UserInterface::handleProgressUpdated);
    
    // API sinyalleri için QObject casting
    if (auto apiManagerQObject = dynamic_cast<QObject*>(m_apiManager.get())) {
        connect(apiManagerQObject, SIGNAL(responseReceived(const QJsonObject&)),
                this, SLOT(onApiResponseReceived(const QJsonObject&)));
        connect(apiManagerQObject, SIGNAL(error(const QString&)),
                this, SLOT(onApiError(const QString&)));
        connect(apiManagerQObject, SIGNAL(requestSent(const QString&)),
                this, SLOT(onApiRequestSent(const QString&)));
    } else {
        qWarning() << "UserInterface: API Manager does not support signal/slot connections!";
    }
}

void UserInterface::initializeUI()
{
    // Ana widget ve layout
    QWidget* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    QHBoxLayout* mainLayout = new QHBoxLayout(centralWidget);
    mainLayout->setSpacing(0);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    
    // Sidebar widget'ı oluştur ve ekle
    m_sidebarWidget = std::make_unique<SidebarWidget>(centralWidget);
    mainLayout->addWidget(m_sidebarWidget.get());
    
    // Ana içerik alanı için container widget
    QWidget* contentContainer = new QWidget(centralWidget);
    QVBoxLayout* contentLayout = new QVBoxLayout(contentContainer);
    contentLayout->setSpacing(20);
    contentLayout->setContentsMargins(30, 30, 30, 30);
    
    // Başlık alanı
    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* logoLabel = new QLabel(this);
    logoLabel->setPixmap(QPixmap(":/images/shield.png").scaled(32, 32, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    logoLabel->setFixedSize(32, 32);
    
    QLabel* titleLabel = new QLabel(tr("Endpoint Protection Platform"), this);
    titleLabel->setObjectName("titleLabel");
    
    headerLayout->addWidget(logoLabel);
    headerLayout->addWidget(titleLabel);
    headerLayout->addStretch();
    
    contentLayout->addLayout(headerLayout);
    
    // Tarama widget'ı oluştur
    m_scanWidget = std::make_unique<ScanWidget>(m_scanManager.get(), contentContainer);
    contentLayout->addWidget(m_scanWidget.get());
    
    // Sonuçlar widget'ı oluştur
    m_resultsWidget = std::make_unique<ResultsWidget>(contentContainer);
    contentLayout->addWidget(m_resultsWidget.get());
    
    // Ana içerik alanını ekle
    mainLayout->addWidget(contentContainer, 1);
    
    // Bağlantılar
    connect(m_sidebarWidget.get(), &SidebarWidget::pageChanged, this, &UserInterface::onPageChanged);
    connect(m_scanWidget.get(), &ScanWidget::scanStarted, m_resultsWidget.get(), &ResultsWidget::showResults);
    
    // ScanManager için UI bileşenlerini ayarla
    m_scanManager->setTextEdit(m_resultsWidget->getResultTextEdit());
    m_scanManager->setLogTextEdit(m_resultsWidget->getApiLogTextEdit());
    m_scanManager->setStatusBar(statusBar());
    
    // ResultsView için UI bileşenlerini ayarla
    m_resultsView->setResultTextEdit(m_resultsWidget->getResultTextEdit());
    m_resultsView->setDetailedResultTextEdit(m_resultsWidget->getDetailedResultTextEdit());
    
    // DockerUIManager için log bileşenini ayarla
    m_dockerUIManager->setLogTextEdit(m_resultsWidget->getApiLogTextEdit());
}

void UserInterface::handleOperationStarted(const QString& operationType)
{
    std::lock_guard<std::mutex> lock(m_progressMutex);
    m_progressDialog->setLabelText(tr("%1 operation starting...").arg(operationType));
    m_progressDialog->setValue(0);
    m_progressDialog->show();
    m_currentProgress = 0;
    
    statusBar()->showMessage(tr("%1 operation started").arg(operationType));
    qApp->processEvents();
}

void UserInterface::handleOperationCompleted(const QString& operationType, bool success)
{
    std::lock_guard<std::mutex> lock(m_progressMutex);
    m_progressDialog->setValue(100);
    m_progressDialog->hide();
    m_currentProgress = 0;
    
    if (success) {
        statusBar()->showMessage(tr("%1 operation completed successfully").arg(operationType), 5000);
    } else {
        statusBar()->showMessage(tr("%1 operation failed").arg(operationType), 5000);
    }
}

void UserInterface::handleProgressUpdated(int percentage)
{
    std::lock_guard<std::mutex> lock(m_progressMutex);
    if (percentage > m_currentProgress) {
        m_currentProgress = percentage;
        m_progressDialog->setValue(percentage);
        qApp->processEvents();
    }
}

void UserInterface::createActions()
{
    // Ana menü aksiyonu
    m_menuAction = new QAction(tr("Menu"), this);
    
    // API Key aksiyonu
    m_apiKeyAction = new QAction(tr("Set API Key"), this);
    m_apiKeyAction->setIcon(QIcon::fromTheme("dialog-password"));
    connect(m_apiKeyAction, &QAction::triggered, this, &UserInterface::onApiKeyButtonClicked);

    // Docker konteyner detayları aksiyonu
    m_dockerAction = new QAction(tr("Docker Container Details"), this);
    m_dockerAction->setIcon(QIcon::fromTheme("docker"));
    connect(m_dockerAction, &QAction::triggered, this, &UserInterface::showContainerDetails);

    // Service Status aksiyonu
    m_serviceStatusAction = new QAction(tr("Service Status"), this);
    m_serviceStatusAction->setIcon(QIcon::fromTheme("dialog-information"));
    connect(m_serviceStatusAction, &QAction::triggered, this, &UserInterface::onServiceStatusButtonClicked);
}

void UserInterface::createMenus()
{
    // Menü butonu oluştur
    QToolButton* menuButton = new QToolButton(this);
    menuButton->setText(tr("Menu"));
    menuButton->setPopupMode(QToolButton::InstantPopup);
    menuButton->setObjectName("menuToolButton");

    // Menü oluştur
    QMenu* menu = new QMenu(this);
    menu->setObjectName("mainMenu");
    
    // Sadeleştirilmiş menü yapısı
    menu->addAction(m_apiKeyAction);
    menu->addAction(m_dockerAction);
    menu->addAction(m_serviceStatusAction);

    menuButton->setMenu(menu);

    // Menü butonunu toolbar'a ekle
    QToolBar* mainToolBar = addToolBar(tr("Main Menu"));
    mainToolBar->setMovable(false);
    mainToolBar->addWidget(menuButton);
    mainToolBar->setObjectName("mainToolBar");
}

void UserInterface::createStatusBar()
{
    // QMainWindow'un kendi statusBar()'ını kullanarak basit bir mesaj gösterebiliriz
    statusBar()->showMessage(tr("Ready"));
}

void UserInterface::onApiResponseReceived(const QJsonObject& response)
{
    if (m_resultsWidget) {
        m_resultsWidget->showApiResponse(response);
    }
}

void UserInterface::onApiError(const QString& errorMessage)
{
    if (m_resultsWidget) {
        m_resultsWidget->logApiError(errorMessage);
    }
}

void UserInterface::onApiRequestSent(const QString& endpoint)
{
    if (m_resultsWidget) {
        m_resultsWidget->logApiRequest(endpoint);
    }
}

void UserInterface::showContainerDetails()
{
    if (m_dockerUIManager) {
        m_dockerUIManager->showContainerDetails();
    }
}

void UserInterface::onPageChanged(SidebarWidget::Page page)
{
    // Sayfa değişimi durumunda yapılacak işlemler
    switch (page) {
        case SidebarWidget::Page::OfflineScan:
        case SidebarWidget::Page::OnlineScan:
        case SidebarWidget::Page::CdrScan:
        case SidebarWidget::Page::Sandbox:
            // Bu sayfalarda ScanWidget görünür olmalı
            if (m_scanWidget) m_scanWidget->setVisible(true);
            break;
            
        case SidebarWidget::Page::ServiceStatus:
            // Service Status diyalogunu göster
            onServiceStatusButtonClicked();
            break;
            
        case SidebarWidget::Page::History:
            // History diyalogunu göster
            try {
                HistoryDialog dialog(this);
                dialog.exec();
                
                // Diyalog kapandıktan sonra, önceki aktif sayfa butonunu seç
                m_sidebarWidget->setActivePage(SidebarWidget::Page::OfflineScan);
            } catch (const std::exception& e) {
                QMessageBox::warning(this, tr("Error"), 
                                   tr("An error occurred while showing history:\n%1").arg(e.what()));
            }
            break;
    }
}

void UserInterface::onApiKeyButtonClicked()
{
    ApiKeyDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted) {
        QString apiKey = dialog.getApiKey();
        if (!apiKey.isEmpty()) {
            try {
                // API key ayarla (güvenlik için key'in sadece ilk 5 karakterini logla)
                qDebug() << "Setting API key:" << apiKey.left(5) + "...";
                
                m_apiManager->setApiKey(apiKey);
                
                if (m_resultsWidget && m_resultsWidget->getApiLogTextEdit()) {
                    m_resultsWidget->getApiLogTextEdit()->appendPlainText(QString("\n🔑 %1 | API key updated")
                        .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
                }
                
                // API key'in doğru şekilde kaydedildiğini kontrol et
                QString storedKey = m_apiManager->getApiKey();
                if (!storedKey.isEmpty()) {
                    QMessageBox::information(this, tr("API Key"), tr("API key successfully saved."));
                } else {
                    QMessageBox::warning(this, tr("API Key"), tr("API key could not be saved."));
                }
            } catch (const std::exception& e) {
                QMessageBox::critical(this, tr("API Key Error"), 
                                    tr("An error occurred while saving the API key: %1").arg(e.what()));
            }
        }
    }
}

void UserInterface::onServiceStatusButtonClicked()
{
    try {
        // Create and show modal dialog - shared_ptr'ler raw pointer'a dönüştürülür
        ServiceStatusDialog dialog(m_apiManager.get(), m_scanManager.get(), m_dockerUIManager.get(), this);
        dialog.exec();
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Error"), 
                           tr("An error occurred while showing service statuses:\n%1").arg(e.what()));
    } catch (...) {
        QMessageBox::warning(this, tr("Error"), 
                           tr("An unknown error occurred while showing service statuses."));
    }
}
