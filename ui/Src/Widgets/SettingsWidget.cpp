#include "Widgets/SettingsWidget.h"
#include <QDir>
#include <QStandardPaths>

SettingsWidget::SettingsWidget(QSettings* settings, QWidget* parent)
    : QWidget(parent),
      m_settings(settings)
{
    if (!m_settings) {
        throw std::runtime_error("SettingsWidget: Settings object cannot be null");
    }
    
    createLayout();
    loadSettings(); // Mevcut ayarları yükle
}

void SettingsWidget::createLayout()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    
    // Başlık
    QLabel* titleLabel = new QLabel(tr("Settings"), this);
    titleLabel->setObjectName("sectionTitleLabel");
    mainLayout->addWidget(titleLabel);
    
    // Tab widget
    m_tabWidget = new QTabWidget(this);
    
    // --- Genel Ayarlar Tab ---
    QWidget* generalTab = new QWidget();
    QVBoxLayout* generalLayout = new QVBoxLayout(generalTab);
    
    QGroupBox* startupGroup = new QGroupBox(tr("Startup and Shutdown"), this);
    QVBoxLayout* startupLayout = new QVBoxLayout(startupGroup);
    
    m_startOnBootCheckbox = new QCheckBox(tr("Start on system boot"), this);
    m_minimizeToTrayCheckbox = new QCheckBox(tr("Minimize to tray when closed"), this);
    m_confirmExitCheckbox = new QCheckBox(tr("Confirm before exit"), this);
    
    startupLayout->addWidget(m_startOnBootCheckbox);
    startupLayout->addWidget(m_minimizeToTrayCheckbox);
    startupLayout->addWidget(m_confirmExitCheckbox);
    
    generalLayout->addWidget(startupGroup);
    generalLayout->addStretch();
    
    // --- Tarama Ayarları Tab ---
    QWidget* scanTab = new QWidget();
    QVBoxLayout* scanLayout = new QVBoxLayout(scanTab);
    
    // Dizinler
    QGroupBox* dirGroup = new QGroupBox(tr("Directories"), this);
    QGridLayout* dirLayout = new QGridLayout(dirGroup);
    
    QLabel* yaraRulesDirLabel = new QLabel(tr("YARA Rules Directory:"), this);
    m_yaraRulesDir = new QLineEdit(this);
    m_yaraRulesDirButton = new QPushButton(tr("Browse..."), this);
    
    QLabel* scanOutputDirLabel = new QLabel(tr("Scan Output Directory:"), this);
    m_scanOutputDir = new QLineEdit(this);
    m_scanOutputDirButton = new QPushButton(tr("Browse..."), this);
    
    dirLayout->addWidget(yaraRulesDirLabel, 0, 0);
    dirLayout->addWidget(m_yaraRulesDir, 0, 1);
    dirLayout->addWidget(m_yaraRulesDirButton, 0, 2);
    
    dirLayout->addWidget(scanOutputDirLabel, 1, 0);
    dirLayout->addWidget(m_scanOutputDir, 1, 1);
    dirLayout->addWidget(m_scanOutputDirButton, 1, 2);
    
    scanLayout->addWidget(dirGroup);
    
    // Tarama Seçenekleri
    QGroupBox* scanOptionsGroup = new QGroupBox(tr("Scan Options"), this);
    QVBoxLayout* scanOptionsLayout = new QVBoxLayout(scanOptionsGroup);
    
    QHBoxLayout* timeoutLayout = new QHBoxLayout();
    QLabel* scanTimeoutLabel = new QLabel(tr("Scan Timeout (seconds):"), this);
    m_scanTimeoutSpinBox = new QSpinBox(this);
    m_scanTimeoutSpinBox->setMinimum(10);
    m_scanTimeoutSpinBox->setMaximum(600);
    m_scanTimeoutSpinBox->setSingleStep(10);
    
    timeoutLayout->addWidget(scanTimeoutLabel);
    timeoutLayout->addWidget(m_scanTimeoutSpinBox);
    timeoutLayout->addStretch();
    
    m_autoScanDownloadsCheckbox = new QCheckBox(tr("Automatically scan downloaded files"), this);
    
    scanOptionsLayout->addLayout(timeoutLayout);
    scanOptionsLayout->addWidget(m_autoScanDownloadsCheckbox);
    
    scanLayout->addWidget(scanOptionsGroup);
    scanLayout->addStretch();
    
    // --- VirusTotal Ayarları Tab ---
    QWidget* vtTab = new QWidget();
    QVBoxLayout* vtLayout = new QVBoxLayout(vtTab);
    
    QGroupBox* vtGroup = new QGroupBox(tr("VirusTotal API Settings"), this);
    QVBoxLayout* vtGroupLayout = new QVBoxLayout(vtGroup);
    
    QHBoxLayout* apiKeyLayout = new QHBoxLayout();
    QLabel* vtApiKeyLabel = new QLabel(tr("API Key:"), this);
    m_virusTotalApiKey = new QLineEdit(this);
    m_virusTotalApiKey->setPlaceholderText(tr("Enter your VirusTotal API key"));
    m_virusTotalApiKey->setEchoMode(QLineEdit::Password);
    
    apiKeyLayout->addWidget(vtApiKeyLabel);
    apiKeyLayout->addWidget(m_virusTotalApiKey, 1);
    
    QHBoxLayout* apiDelayLayout = new QHBoxLayout();
    QLabel* apiDelayLabel = new QLabel(tr("API Request Delay (seconds):"), this);
    m_apiRequestDelaySpinBox = new QSpinBox(this);
    m_apiRequestDelaySpinBox->setMinimum(1);
    m_apiRequestDelaySpinBox->setMaximum(60);
    
    apiDelayLayout->addWidget(apiDelayLabel);
    apiDelayLayout->addWidget(m_apiRequestDelaySpinBox);
    apiDelayLayout->addStretch();
    
    m_submitHashesOnlyCheckbox = new QCheckBox(tr("Submit file hashes only (Privacy mode)"), this);
    
    vtGroupLayout->addLayout(apiKeyLayout);
    vtGroupLayout->addLayout(apiDelayLayout);
    vtGroupLayout->addWidget(m_submitHashesOnlyCheckbox);
    
    vtLayout->addWidget(vtGroup);
    vtLayout->addStretch();
    
    // Tabları ekle
    m_tabWidget->addTab(generalTab, tr("General"));
    m_tabWidget->addTab(scanTab, tr("Scanning"));
    m_tabWidget->addTab(vtTab, tr("VirusTotal"));
    
    mainLayout->addWidget(m_tabWidget);
    
    // Butonlar
    QHBoxLayout* buttonsLayout = new QHBoxLayout();
    m_resetButton = new QPushButton(tr("Reset to Defaults"), this);
    m_applyButton = new QPushButton(tr("Apply"), this);
    m_applyButton->setDefault(true);
    
    buttonsLayout->addWidget(m_resetButton);
    buttonsLayout->addStretch();
    buttonsLayout->addWidget(m_applyButton);
    
    mainLayout->addLayout(buttonsLayout);
    
    // Sinyal-slot bağlantıları
    connect(m_yaraRulesDirButton, &QPushButton::clicked, this, &SettingsWidget::selectYaraRulesDir);
    connect(m_scanOutputDirButton, &QPushButton::clicked, this, &SettingsWidget::selectScanOutputDir);
    connect(m_applyButton, &QPushButton::clicked, this, &SettingsWidget::saveSettings);
    connect(m_resetButton, &QPushButton::clicked, this, &SettingsWidget::resetToDefaults);
    
    setLayout(mainLayout);
}

void SettingsWidget::loadSettings()
{
    // Genel Ayarlar
    m_startOnBootCheckbox->setChecked(m_settings->value("General/StartOnBoot", false).toBool());
    m_minimizeToTrayCheckbox->setChecked(m_settings->value("General/MinimizeToTray", true).toBool());
    m_confirmExitCheckbox->setChecked(m_settings->value("General/ConfirmExit", true).toBool());
    
    // Tarama Ayarları
    m_yaraRulesDir->setText(m_settings->value("Scanning/YaraRulesDir", QDir::currentPath() + "/Rules").toString());
    m_scanOutputDir->setText(m_settings->value("Scanning/OutputDir", 
                                             QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/EPP_Scans").toString());
    m_scanTimeoutSpinBox->setValue(m_settings->value("Scanning/Timeout", 60).toInt());
    m_autoScanDownloadsCheckbox->setChecked(m_settings->value("Scanning/AutoScanDownloads", false).toBool());
    
    // VirusTotal Ayarları
    m_virusTotalApiKey->setText(m_settings->value("VirusTotal/ApiKey", "").toString());
    m_submitHashesOnlyCheckbox->setChecked(m_settings->value("VirusTotal/SubmitHashesOnly", true).toBool());
    m_apiRequestDelaySpinBox->setValue(m_settings->value("VirusTotal/RequestDelay", 15).toInt());
}

void SettingsWidget::loadDefaults()
{
    // Genel Ayarlar
    m_startOnBootCheckbox->setChecked(false);
    m_minimizeToTrayCheckbox->setChecked(true);
    m_confirmExitCheckbox->setChecked(true);
    
    // Tarama Ayarları
    m_yaraRulesDir->setText(QDir::currentPath() + "/Rules");
    m_scanOutputDir->setText(QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/EPP_Scans");
    m_scanTimeoutSpinBox->setValue(60);
    m_autoScanDownloadsCheckbox->setChecked(false);
    
    // VirusTotal Ayarları
    m_virusTotalApiKey->clear();
    m_submitHashesOnlyCheckbox->setChecked(true);
    m_apiRequestDelaySpinBox->setValue(15);
}

void SettingsWidget::selectYaraRulesDir()
{
    QString dir = QFileDialog::getExistingDirectory(this,
                                                  tr("Select YARA Rules Directory"),
                                                  m_yaraRulesDir->text(),
                                                  QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    
    if (!dir.isEmpty()) {
        m_yaraRulesDir->setText(dir);
    }
}

void SettingsWidget::selectScanOutputDir()
{
    QString dir = QFileDialog::getExistingDirectory(this,
                                                  tr("Select Scan Output Directory"),
                                                  m_scanOutputDir->text(),
                                                  QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    
    if (!dir.isEmpty()) {
        m_scanOutputDir->setText(dir);
    }
}

void SettingsWidget::saveSettings()
{
    applySettings(true);
}

void SettingsWidget::resetToDefaults()
{
    int result = QMessageBox::question(this,
                                      tr("Reset Settings"),
                                      tr("Are you sure you want to reset all settings to default values?"),
                                      QMessageBox::Yes | QMessageBox::No,
                                      QMessageBox::No);
    
    if (result == QMessageBox::Yes) {
        loadDefaults();
        applySettings(true);
    }
}

void SettingsWidget::applySettings(bool showConfirmation)
{
    // Genel Ayarlar
    m_settings->setValue("General/StartOnBoot", m_startOnBootCheckbox->isChecked());
    m_settings->setValue("General/MinimizeToTray", m_minimizeToTrayCheckbox->isChecked());
    m_settings->setValue("General/ConfirmExit", m_confirmExitCheckbox->isChecked());
    
    // Tarama Ayarları
    m_settings->setValue("Scanning/YaraRulesDir", m_yaraRulesDir->text());
    m_settings->setValue("Scanning/OutputDir", m_scanOutputDir->text());
    m_settings->setValue("Scanning/Timeout", m_scanTimeoutSpinBox->value());
    m_settings->setValue("Scanning/AutoScanDownloads", m_autoScanDownloadsCheckbox->isChecked());
    
    // VirusTotal Ayarları
    m_settings->setValue("VirusTotal/ApiKey", m_virusTotalApiKey->text());
    m_settings->setValue("VirusTotal/SubmitHashesOnly", m_submitHashesOnlyCheckbox->isChecked());
    m_settings->setValue("VirusTotal/RequestDelay", m_apiRequestDelaySpinBox->value());
    
    // Ayarları kaydet
    m_settings->sync();
    
    // Çıktı dizininin varlığını kontrol et ve gerekirse oluştur
    QDir outputDir(m_scanOutputDir->text());
    if (!outputDir.exists()) {
        outputDir.mkpath(".");
    }
    
    if (showConfirmation) {
        QMessageBox::information(this, tr("Settings Saved"), tr("Your settings have been saved successfully."));
    }
}