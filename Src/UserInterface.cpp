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

    // Ana pencere boyutu ve stili
    QScreen *screen = QApplication::primaryScreen();
    QRect screenGeometry = screen->geometry();
    int width = screenGeometry.width() * 0.8;
    int height = screenGeometry.height() * 0.8;
    resize(width, height);
    setMinimumSize(800, 600);

    // Genel stil ayarları
    setStyleSheet(
        "QMainWindow {"
        "    background-color: #f5f6fa;"
        "}"
        "QToolBar {"
        "    background-color: #f5f6fa;"
        "    border: none;"
        "    spacing: 10px;"
        "    padding: 5px;"
        "}"
    );

    createActions();
    createMenus();
    createStatusBar();
    createCentralWidgets();

    setWindowTitle(tr("Windows Antivirüs"));
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
        "    background-color: #2c3e50;"
        "    color: white;"
        "    border: none;"
        "    padding: 8px 16px;"
        "    font-size: 12pt;"
        "    border-radius: 5px;"
        "}"
        "QToolButton:hover {"
        "    background-color: #34495e;"
        "}"
        "QToolButton::menu-indicator {"
        "    image: none;"
        "}"
    );

    // Menü oluştur
    QMenu* menu = new QMenu(this);
    menu->setStyleSheet(
        "QMenu {"
        "    background-color: white;"
        "    border: 1px solid #bdc3c7;"
        "    border-radius: 5px;"
        "    padding: 5px;"
        "}"
        "QMenu::item {"
        "    padding: 8px 25px 8px 15px;"
        "    border-radius: 3px;"
        "    margin: 2px;"
        "    color: #2c3e50;"
        "}"
        "QMenu::item:selected {"
        "    background-color: #3498db;"
        "    color: white;"
        "}"
        "QMenu::separator {"
        "    height: 1px;"
        "    background-color: #bdc3c7;"
        "    margin: 5px 15px;"
        "}"
    );

    menu->addAction(scanAction);
    menu->addAction(virusTotalAction);
    menu->addSeparator();
    menu->addAction(apiKeyAction);

    menuButton->setMenu(menu);

    // Toolbar'a menü butonunu ekle
    QToolBar* mainToolBar = addToolBar(tr("Ana Menü"));
    mainToolBar->setMovable(false);
    mainToolBar->addWidget(menuButton);
    mainToolBar->setStyleSheet(
        "QToolBar {"
        "    background-color: #f5f6fa;"
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

// Merkezdeki widget ve layout
void MainWindow::createCentralWidgets()
{
    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->setSpacing(20);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    // Ana splitter oluştur
    QSplitter *mainSplitter = new QSplitter(Qt::Vertical, this);
    mainSplitter->setStyleSheet(
        "QSplitter::handle {"
        "    background-color: #bdc3c7;"
        "    height: 2px;"
        "}"
    );

    // Üst kısım - Sonuçlar için tab widget
    QTabWidget *tabWidget = new QTabWidget(this);
    tabWidget->setStyleSheet(
        "QTabWidget::pane {"
        "    border: 2px solid #bdc3c7;"
        "    border-radius: 8px;"
        "    background-color: white;"
        "    padding: 10px;"
        "}"
        "QTabBar::tab {"
        "    background-color: #ecf0f1;"
        "    color: #2c3e50;"
        "    padding: 10px 20px;"
        "    border: 1px solid #bdc3c7;"
        "    border-bottom: none;"
        "    border-top-left-radius: 4px;"
        "    border-top-right-radius: 4px;"
        "    margin-right: 2px;"
        "    font-size: 11pt;"
        "}"
        "QTabBar::tab:selected {"
        "    background-color: white;"
        "    border-bottom: none;"
        "    margin-bottom: -1px;"
        "}"
        "QTabBar::tab:hover {"
        "    background-color: #f5f6fa;"
        "}"
    );

    // Normal mod için widget
    QWidget *normalModeWidget = new QWidget();
    QVBoxLayout *normalLayout = new QVBoxLayout(normalModeWidget);
    resultTextEdit = new QPlainTextEdit();
    resultTextEdit->setReadOnly(true);
    setupTextEditStyle(resultTextEdit);
    normalLayout->addWidget(resultTextEdit);

    // Detaylı mod için widget
    QWidget *detailedModeWidget = new QWidget();
    QVBoxLayout *detailedLayout = new QVBoxLayout(detailedModeWidget);
    detailedResultTextEdit = new QPlainTextEdit();
    detailedResultTextEdit->setReadOnly(true);
    setupTextEditStyle(detailedResultTextEdit);
    detailedLayout->addWidget(detailedResultTextEdit);

    tabWidget->addTab(normalModeWidget, "🔍 Normal Görünüm");
    tabWidget->addTab(detailedModeWidget, "🔬 Detaylı Görünüm");

    // Alt kısım - API İstekleri için grup kutusu
    QGroupBox *apiGroup = new QGroupBox("API İletişimi", this);
    apiGroup->setStyleSheet(
        "QGroupBox {"
        "    font-size: 12pt;"
        "    font-weight: bold;"
        "    border: 2px solid #bdc3c7;"
        "    border-radius: 8px;"
        "    margin-top: 1ex;"
        "    padding: 10px;"
        "    background-color: white;"
        "}"
        "QGroupBox::title {"
        "    subcontrol-origin: margin;"
        "    subcontrol-position: top center;"
        "    padding: 0 10px;"
        "    color: #2c3e50;"
        "    background-color: white;"
        "}"
    );

    QVBoxLayout *apiLayout = new QVBoxLayout(apiGroup);
    apiLogTextEdit = new QPlainTextEdit();
    apiLogTextEdit->setReadOnly(true);
    setupTextEditStyle(apiLogTextEdit);
    apiLogTextEdit->setMaximumHeight(150);
    apiLayout->addWidget(apiLogTextEdit);

    // Splitter'a widget'ları ekle
    mainSplitter->addWidget(tabWidget);
    mainSplitter->addWidget(apiGroup);
    mainSplitter->setStretchFactor(0, 2);  // Üst kısım daha fazla yer kaplasın
    mainSplitter->setStretchFactor(1, 1);

    mainLayout->addWidget(mainSplitter);

    // Durum çubuğu
    statusLabel = new QLabel(tr("Hazır"), this);
    statusLabel->setStyleSheet(
        "QLabel {"
        "    font-size: 11pt;"
        "    color: #2c3e50;"
        "    padding: 10px;"
        "    background-color: white;"
        "    border: 1px solid #bdc3c7;"
        "    border-radius: 5px;"
        "}"
    );
    mainLayout->addWidget(statusLabel);
}

void MainWindow::setupTextEditStyle(QPlainTextEdit* textEdit) {
    textEdit->setStyleSheet(
        "QPlainTextEdit {"
        "    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;"
        "    font-size: 12pt;"
        "    line-height: 1.5;"
        "    padding: 15px;"
        "    background-color: white;"
        "    color: #2c3e50;"
        "    border: none;"
        "}"
    );
    QFont font = textEdit->font();
    font.setPointSize(12);
    textEdit->setFont(font);
}

// API isteği gönderildiğinde
void MainWindow::onApiRequestSent(const QString& endpoint) {
    apiLogTextEdit->appendPlainText(QString("📤 Gönderilen İstek [%1]: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(endpoint));
}

// API yanıtı alındığında
void MainWindow::onApiResponseReceived(const QJsonObject& response) {
    // Normal görünüm için basit sonuçlar
    resultTextEdit->clear();
    showNormalResults(response);

    // Detaylı görünüm için tüm sonuçlar
    detailedResultTextEdit->clear();
    showDetailedResults(response);

    // API log'una yanıtı ekle
    apiLogTextEdit->appendPlainText(QString("\n📥 Alınan Yanıt [%1]:")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
}

void MainWindow::showNormalResults(const QJsonObject& response) {
    if (!response.contains("data")) {
        resultTextEdit->appendPlainText("❌ Üzgünüz, dosya tarama sonuçları alınamadı.");
        return;
    }

    QJsonObject data = response["data"].toObject();
    if (!data.contains("attributes")) {
        resultTextEdit->appendPlainText("❌ Dosya analiz sonuçları bulunamadı.");
        return;
    }

    QJsonObject attributes = data["attributes"].toObject();
    
    // Başlık
    resultTextEdit->appendPlainText("=== Dosya Güvenlik Raporu ===\n");
    
    // Genel Değerlendirme
    if (attributes.contains("stats")) {
        QJsonObject stats = attributes["stats"].toObject();
        int malicious = stats["malicious"].toInt();
        int suspicious = stats["suspicious"].toInt();
        
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
    if (attributes.contains("meaningful_name")) {
        resultTextEdit->appendPlainText(QString("📝 Dosya Adı: %1").arg(attributes["meaningful_name"].toString()));
    }
    if (attributes.contains("type_description")) {
        resultTextEdit->appendPlainText(QString("📁 Dosya Türü: %1").arg(attributes["type_description"].toString()));
    }
    if (attributes.contains("size")) {
        double sizeInMB = attributes["size"].toDouble() / (1024 * 1024);
        resultTextEdit->appendPlainText(QString("💾 Boyut: %.2f MB").arg(sizeInMB));
    }

    // Topluluk Değerlendirmesi
    if (attributes.contains("total_votes")) {
        QJsonObject votes = attributes["total_votes"].toObject();
        int harmlessVotes = votes["harmless"].toInt();
        int maliciousVotes = votes["malicious"].toInt();
        
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
    if (attributes.contains("stats")) {
        QJsonObject stats = attributes["stats"].toObject();
        int malicious = stats["malicious"].toInt();
        int suspicious = stats["suspicious"].toInt();
        
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
    if (!response.contains("data")) {
        detailedResultTextEdit->appendPlainText("❌ Detaylı analiz sonuçları alınamadı.");
        return;
    }

    QJsonObject data = response["data"].toObject();
    if (!data.contains("attributes")) {
        detailedResultTextEdit->appendPlainText("❌ Dosya özellikleri bulunamadı.");
        return;
    }

    QJsonObject attributes = data["attributes"].toObject();
    
    // Başlık
    detailedResultTextEdit->appendPlainText("=== Detaylı Analiz Raporu ===\n");
    
    // İstatistikler
    if (attributes.contains("stats")) {
        QJsonObject stats = attributes["stats"].toObject();
        detailedResultTextEdit->appendPlainText("📊 TARAMA İSTATİSTİKLERİ");
        detailedResultTextEdit->appendPlainText("------------------------");
        detailedResultTextEdit->appendPlainText(QString("📌 Toplam Tarama: %1").arg(stats["total"].toInt()));
        detailedResultTextEdit->appendPlainText(QString("🔴 Zararlı: %1").arg(stats["malicious"].toInt()));
        detailedResultTextEdit->appendPlainText(QString("🟡 Şüpheli: %1").arg(stats["suspicious"].toInt()));
        detailedResultTextEdit->appendPlainText(QString("🟢 Temiz: %1").arg(stats["harmless"].toInt()));
        detailedResultTextEdit->appendPlainText(QString("⚪ Analiz Edilemedi: %1\n").arg(stats["undetected"].toInt()));
    }

    // Detaylı Dosya Bilgileri
    detailedResultTextEdit->appendPlainText("\n📄 DETAYLI DOSYA BİLGİLERİ");
    detailedResultTextEdit->appendPlainText("------------------------");
    if (attributes.contains("meaningful_name")) {
        detailedResultTextEdit->appendPlainText(QString("📝 Dosya Adı: %1").arg(attributes["meaningful_name"].toString()));
    }
    if (attributes.contains("type_description")) {
        detailedResultTextEdit->appendPlainText(QString("📁 Dosya Türü: %1").arg(attributes["type_description"].toString()));
    }
    if (attributes.contains("size")) {
        double sizeInMB = attributes["size"].toDouble() / (1024 * 1024);
        detailedResultTextEdit->appendPlainText(QString("💾 Boyut: %.2f MB").arg(sizeInMB));
    }
    if (attributes.contains("md5")) {
        detailedResultTextEdit->appendPlainText(QString("🔑 MD5: %1").arg(attributes["md5"].toString()));
    }
    if (attributes.contains("sha1")) {
        detailedResultTextEdit->appendPlainText(QString("🔑 SHA1: %1").arg(attributes["sha1"].toString()));
    }
    if (attributes.contains("sha256")) {
        detailedResultTextEdit->appendPlainText(QString("🔑 SHA256: %1").arg(attributes["sha256"].toString()));
    }
    if (attributes.contains("first_submission_date")) {
        QDateTime firstSeen = QDateTime::fromSecsSinceEpoch(attributes["first_submission_date"].toInt());
        detailedResultTextEdit->appendPlainText(QString("🕒 İlk Görülme: %1").arg(firstSeen.toString("dd.MM.yyyy hh:mm")));
    }
    if (attributes.contains("last_analysis_date")) {
        QDateTime lastAnalysis = QDateTime::fromSecsSinceEpoch(attributes["last_analysis_date"].toInt());
        detailedResultTextEdit->appendPlainText(QString("🕒 Son Analiz: %1").arg(lastAnalysis.toString("dd.MM.yyyy hh:mm")));
    }

    // Davranış Analizi
    if (attributes.contains("sandbox_verdicts")) {
        detailedResultTextEdit->appendPlainText("\n🔍 SANDBOX ANALİZ SONUÇLARI");
        detailedResultTextEdit->appendPlainText("------------------------");
        QJsonObject sandboxResults = attributes["sandbox_verdicts"].toObject();
        
        for (auto it = sandboxResults.begin(); it != sandboxResults.end(); ++it) {
            QJsonObject verdict = it.value().toObject();
            QString category = verdict["category"].toString();
            QString explanation = verdict["explanation"].toString();
            
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
    if (attributes.contains("behavior")) {
        QJsonObject behavior = attributes["behavior"].toObject();
        detailedResultTextEdit->appendPlainText("\n🔄 DAVRANIŞSAL ANALİZ");
        detailedResultTextEdit->appendPlainText("------------------------");
        
        // Network aktivitesi
        if (behavior.contains("network_activity")) {
            QJsonValue networkValue = behavior["network_activity"];
            if (networkValue.isArray()) {
                detailedResultTextEdit->appendPlainText("\n   🌐 Ağ Aktivitesi:");
                QJsonArray networkActivity = networkValue.toArray();
                for (const QJsonValue &activity : networkActivity) {
                    detailedResultTextEdit->appendPlainText(QString("   - %1").arg(activity.toString()));
                }
            }
        }
        
        // Dosya sistemi aktivitesi
        if (behavior.contains("filesystem_activity")) {
            QJsonValue fsValue = behavior["filesystem_activity"];
            if (fsValue.isArray()) {
                detailedResultTextEdit->appendPlainText("\n   💽 Dosya Sistemi Aktivitesi:");
                QJsonArray fsActivity = fsValue.toArray();
                for (const QJsonValue &activity : fsActivity) {
                    detailedResultTextEdit->appendPlainText(QString("   - %1").arg(activity.toString()));
                }
            }
        }
        
        // Registry aktivitesi
        if (behavior.contains("registry_activity")) {
            QJsonValue regValue = behavior["registry_activity"];
            if (regValue.isArray()) {
                detailedResultTextEdit->appendPlainText("\n   🔧 Registry Aktivitesi:");
                QJsonArray regActivity = regValue.toArray();
                for (const QJsonValue &activity : regActivity) {
                    detailedResultTextEdit->appendPlainText(QString("   - %1").arg(activity.toString()));
                }
            }
        }
    }

    // Detaylı Antivirüs Sonuçları
    if (attributes.contains("last_analysis_results")) {
        detailedResultTextEdit->appendPlainText("\n🛡️ DETAYLI ANTİVİRÜS SONUÇLARI");
        detailedResultTextEdit->appendPlainText("------------------------");
        QJsonObject results = attributes["last_analysis_results"].toObject();
        
        QStringList malicious, suspicious, clean;
        
        for (auto it = results.begin(); it != results.end(); ++it) {
            QString engine = it.key();
            QJsonObject result = it.value().toObject();
            QString category = result["category"].toString();
            QString resultStr = result["result"].toString();
            QString version = result["engine_version"].toString();
            QString update = result["engine_update"].toString();
            
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
        
        // Temiz sonuçlar
        detailedResultTextEdit->appendPlainText("\n🟢 Temiz Sonuç Veren Antivirüsler:");
        for (const QString& entry : clean) {
            detailedResultTextEdit->appendPlainText("  ✓ " + entry);
        }
    }

    // Topluluk Değerlendirmesi
    if (attributes.contains("total_votes")) {
        QJsonObject votes = attributes["total_votes"].toObject();
        int harmlessVotes = votes["harmless"].toInt();
        int maliciousVotes = votes["malicious"].toInt();
        
        if (harmlessVotes > 0 || maliciousVotes > 0) {
            detailedResultTextEdit->appendPlainText("\n👥 TOPLULUK DEĞERLENDİRMESİ");
            detailedResultTextEdit->appendPlainText("------------------------");
            detailedResultTextEdit->appendPlainText(QString("👍 Güvenli Oylar: %1").arg(harmlessVotes));
            detailedResultTextEdit->appendPlainText(QString("👎 Zararlı Oylar: %1").arg(maliciousVotes));
            
            // Oy oranı hesapla
            double totalVotes = harmlessVotes + maliciousVotes;
            double harmlessPercentage = (harmlessVotes / totalVotes) * 100;
            double maliciousPercentage = (maliciousVotes / totalVotes) * 100;
            
            detailedResultTextEdit->appendPlainText(QString("📊 Güvenli Oy Oranı: %.1f%%").arg(harmlessPercentage));
            detailedResultTextEdit->appendPlainText(QString("📊 Zararlı Oy Oranı: %.1f%%").arg(maliciousPercentage));
        }
    }
}

// -- Tarama Yap tıklanınca --
void MainWindow::onScanButtonClicked()
{
    // Dosya seçme
    QString filePath = QFileDialog::getOpenFileName(this, tr("Dosya Seç"), QString(), tr("Tüm Dosyalar (*.*)"));
    if (filePath.isEmpty()) {
        statusLabel->setText("Dosya seçilmedi.");
        return;
    }
    statusLabel->setText("Dosya seçildi. Hash hesaplamaları yapılıyor...");

    // Hash hesaplamaları
    QString md5Hash    = HashCalculation::Md5Hashing(filePath);
    QString sha1Hash   = HashCalculation::Sha1Hashing(filePath);
    QString sha256Hash = HashCalculation::Sha256Hashing(filePath);

    // Veritabanı aramaları
    QString md5Result    = DbManager::searchHashmMd5(md5Hash);
    QString sha1Result   = DbManager::searchHashSha_1(sha1Hash);
    QString sha256Result = DbManager::searchHashSha_256(sha256Hash);

    // Sonuçları ekranda göstermek için resultTextEdit'i temizleyip yazalım
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
    statusLabel->setText("YARA kuralları yükleniyor...");
    std::string yaraRulePath = "Rules/test.yar"; // Test kural dosyası
    std::error_code yaraErr = yaraManager->loadRules(yaraRulePath);
    if (yaraErr) {
        resultTextEdit->appendPlainText(QString("YARA kural dosyası yüklenemedi: %1").arg(QString::fromStdString(yaraErr.message())));
        statusLabel->setText("YARA kuralı yüklenemedi");
        return;
    }
    // Kural derleme adımı eklendi
    std::error_code compileErr = yaraManager->compileRules();
    if (compileErr) {
        resultTextEdit->appendPlainText(QString("YARA kural derleme hatası: %1").arg(QString::fromStdString(compileErr.message())));
        statusLabel->setText("YARA kural derleme hatası");
        return;
    }
    resultTextEdit->appendPlainText("YARA kuralları başarıyla yüklendi. Dosya taranıyor...");
    statusLabel->setText("YARA ile dosya taranıyor...");
    std::vector<std::string> yaraMatches;
    std::error_code scanErr = yaraManager->scanFile(filePath.toStdString(), yaraMatches);
    if (scanErr) {
        resultTextEdit->appendPlainText(QString("YARA tarama hatası: %1").arg(QString::fromStdString(scanErr.message())));
        statusLabel->setText("YARA tarama hatası");
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
    statusLabel->setText("Tarama tamamlandı.");
}

// -- Virustotal Scan tıklanınca --
void MainWindow::onsendVirusTotalButtonClicked() {
    if (!apiManager->hasApiKey()) {
        QMessageBox::warning(this, "Uyarı", "Lütfen önce API key ayarlayın");
        return;
    }

    // Dosya seçme
    QString filePath = QFileDialog::getOpenFileName(this, tr("Dosya Seç"), QString(), tr("Tüm Dosyalar (*.*)"));
    if (filePath.isEmpty()) {
        updateStatus("Dosya seçilmedi");
        return;
    }

    updateStatus("Dosya seçildi. Hash hesaplanıyor...");

    // Hash hesaplamaları
    QString sha256Hash = HashCalculation::Sha256Hashing(filePath);

    updateStatus("VirusTotal'e sorgu gönderiliyor...");
    // VirusTotal API v3 endpoint'i için doğru formatta istek yap
    apiManager->makeApiRequest(QString("/files/%1").arg(sha256Hash));
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
    statusLabel->setText(message);
}

void MainWindow::appendResult(const QString& engine, const QString& result) {
    resultTextEdit->appendPlainText(QString("%1: %2").arg(engine, result));
}
