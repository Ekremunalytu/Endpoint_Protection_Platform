#include "Widgets/ScanWidget.h"
#include "ScanManager.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QProgressBar>
#include <QTextEdit>
#include <QDateTime>

ScanWidget::ScanWidget(ScanManager* scanManager, QWidget* parent)
    : QWidget(parent),
      m_scanManager(scanManager)
{
    if (!m_scanManager) {
        throw std::runtime_error("ScanWidget: ScanManager cannot be null");
    }
    
    createLayout();
    setupConnections();
}

void ScanWidget::createLayout()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    
    // Başlık
    QLabel* titleLabel = new QLabel(tr("Security Scans"), this);
    titleLabel->setObjectName("sectionTitleLabel");
    mainLayout->addWidget(titleLabel);
    
    // Butonlar için ortak stil tanımı
    auto createScanButton = [this](const QString& text) -> QPushButton* {
        QPushButton* btn = new QPushButton(text, this);
        btn->setObjectName("scanButton");
        btn->setMinimumHeight(50);
        return btn;
    };
    
    // Scan butonları
    m_offlineScanBtn = createScanButton(tr("Offline Scan"));
    m_virusTotalScanBtn = createScanButton(tr("Online Scan (VirusTotal)"));
    m_cdrScanBtn = createScanButton(tr("Content Disarm and Reconstruction"));
    m_sandboxScanBtn = createScanButton(tr("Sandbox Analysis"));
    
    mainLayout->addWidget(m_offlineScanBtn);
    mainLayout->addWidget(m_virusTotalScanBtn);
    mainLayout->addWidget(m_cdrScanBtn);
    mainLayout->addWidget(m_sandboxScanBtn);
    
    // İlerleme göstergesi ekle
    QHBoxLayout* progressLayout = new QHBoxLayout();
    QLabel* progressLabel = new QLabel(tr("Progress:"), this);
    m_progressBar = new QProgressBar(this);
    m_progressBar->setMinimum(0);
    m_progressBar->setMaximum(100);
    m_progressBar->setValue(0);
    m_progressBar->setTextVisible(true);
    m_progressBar->setVisible(false);
    
    progressLayout->addWidget(progressLabel);
    progressLayout->addWidget(m_progressBar, 1);
    mainLayout->addLayout(progressLayout);
    
    // Sonuç alanı ekle
    QLabel* resultsLabel = new QLabel(tr("Scan Results:"), this);
    m_resultsTextEdit = new QTextEdit(this);
    m_resultsTextEdit->setReadOnly(true);
    m_resultsTextEdit->setMinimumHeight(200);
    m_resultsTextEdit->setVisible(false);
    
    mainLayout->addWidget(resultsLabel);
    mainLayout->addWidget(m_resultsTextEdit);
    
    mainLayout->addStretch();
    
    setLayout(mainLayout);
}

void ScanWidget::setupConnections()
{
    // Scan butonları bağlantıları
    connect(m_offlineScanBtn, &QPushButton::clicked, this, &ScanWidget::onOfflineScanClicked);
    connect(m_virusTotalScanBtn, &QPushButton::clicked, this, &ScanWidget::onVirusTotalScanClicked);
    connect(m_cdrScanBtn, &QPushButton::clicked, this, &ScanWidget::onCdrScanClicked);
    connect(m_sandboxScanBtn, &QPushButton::clicked, this, &ScanWidget::onSandboxScanClicked);
    
    // ScanManager sinyal bağlantıları
    connect(m_scanManager, &ScanManager::scanProgressUpdated, this, &ScanWidget::updateProgress);
    connect(m_scanManager, &ScanManager::scanCompleted, this, &ScanWidget::displayResults);
    connect(m_scanManager, &ScanManager::scanError, this, &ScanWidget::displayError);
}

void ScanWidget::updateProgress(int progress)
{
    m_progressBar->setValue(progress);
    
    // Eğer progress bar görünür değilse görünür yap
    if (!m_progressBar->isVisible()) {
        m_progressBar->setVisible(true);
    }
}

void ScanWidget::displayResults(const QString& scanType, const QString& filePath, const QString& result, bool isClean)
{
    // İlerleme çubuğunu tamamlanmış olarak işaretle
    m_progressBar->setValue(100);
    
    // Sonuç metnini oluştur
    QString resultText = QString("<h3>%1 - %2</h3>")
                             .arg(scanType)
                             .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
    
    resultText += QString("<p><b>File:</b> %1</p>").arg(filePath);
    
    if (isClean) {
        resultText += QString("<p style='color:green'><b>Status:</b> Clean</p>");
    } else {
        resultText += QString("<p style='color:red'><b>Status:</b> Potential threat detected</p>");
    }
    
    resultText += QString("<p><b>Details:</b> %1</p>").arg(result);
    
    // Sonuç alanını güncelle
    m_resultsTextEdit->setVisible(true);
    m_resultsTextEdit->setHtml(resultText);
}

void ScanWidget::displayError(const QString& error)
{
    // İlerleme çubuğunu sıfırla
    m_progressBar->setValue(0);
    m_progressBar->setVisible(false);
    
    // Hata mesajını sonuç alanına ekle
    QString errorText = QString("<h3>Error - %1</h3>")
                            .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
    
    errorText += QString("<p style='color:red'><b>Error:</b> %1</p>").arg(error);
    
    m_resultsTextEdit->setVisible(true);
    m_resultsTextEdit->setHtml(errorText);
}

void ScanWidget::onOfflineScanClicked()
{
    try {
        QString filePath = QFileDialog::getOpenFileName(this, 
                                                       tr("Select File to Scan"),
                                                       QDir::homePath(),
                                                       tr("All Files (*.*)"));
        if (filePath.isEmpty()) {
            return; // Kullanıcı iptal etti
        }
        
        // Sonuç alanını hazırla ve ilerleme göstergesini resetle
        m_resultsTextEdit->clear();
        m_resultsTextEdit->setVisible(true);
        m_progressBar->setValue(0);
        m_progressBar->setVisible(true);
        
        // Kullanıcıya işlemin başladığını bildir
        m_resultsTextEdit->setHtml(tr("<p>Starting offline scan for file: %1</p>").arg(filePath));
        
        // ScanManager üzerinden taramayı başlat
        emit scanStarted(true);
        m_scanManager->performOfflineScan(filePath);
    }
    catch (const std::exception& e) {
        displayError(tr("An error occurred during offline scan: %1").arg(e.what()));
    }
}

void ScanWidget::onVirusTotalScanClicked()
{
    try {
        QString filePath = QFileDialog::getOpenFileName(this, 
                                                       tr("Select File to Send to VirusTotal"),
                                                       QDir::homePath(),
                                                       tr("All Files (*.*)"));
        if (filePath.isEmpty()) {
            return; // Kullanıcı iptal etti
        }
        
        // Sonuç alanını hazırla ve ilerleme göstergesini resetle
        m_resultsTextEdit->clear();
        m_resultsTextEdit->setVisible(true);
        m_progressBar->setValue(0);
        m_progressBar->setVisible(true);
        
        // Kullanıcıya işlemin başladığını bildir
        m_resultsTextEdit->setHtml(tr("<p>Starting VirusTotal scan for file: %1</p>").arg(filePath));
        
        // ScanManager üzerinden online taramayı başlat
        emit scanStarted(true);
        m_scanManager->performOnlineScan(filePath);
    }
    catch (const std::exception& e) {
        displayError(tr("An error occurred during VirusTotal scan: %1").arg(e.what()));
    }
}

void ScanWidget::onCdrScanClicked()
{
    try {
        QString filePath = QFileDialog::getOpenFileName(this, 
                                                       tr("Select File for CDR Process"),
                                                       QDir::homePath(),
                                                       tr("Office and PDF Files (*.docx *.xlsx *.pptx *.pdf);;All Files (*.*)"));
        if (filePath.isEmpty()) {
            return; // Kullanıcı iptal etti
        }
        
        // Sonuç alanını hazırla ve ilerleme göstergesini resetle
        m_resultsTextEdit->clear();
        m_resultsTextEdit->setVisible(true);
        m_progressBar->setValue(0);
        m_progressBar->setVisible(true);
        
        // Kullanıcıya işlemin başladığını bildir
        m_resultsTextEdit->setHtml(tr("<p>Starting Content Disarm and Reconstruction for file: %1</p>").arg(filePath));
        
        // ScanManager üzerinden CDR taramasını başlat
        emit scanStarted(true);
        m_scanManager->performCdrScan(filePath);
    }
    catch (const std::exception& e) {
        displayError(tr("An error occurred during CDR process: %1").arg(e.what()));
    }
}

void ScanWidget::onSandboxScanClicked()
{
    try {
        QString filePath = QFileDialog::getOpenFileName(this, 
                                                       tr("Select File for Sandbox Analysis"),
                                                       QDir::homePath(),
                                                       tr("Executable Files (*.exe *.dll *.bat *.js *.vbs);;All Files (*.*)"));
        if (filePath.isEmpty()) {
            return; // Kullanıcı iptal etti
        }
        
        // Sonuç alanını hazırla ve ilerleme göstergesini resetle
        m_resultsTextEdit->clear();
        m_resultsTextEdit->setVisible(true);
        m_progressBar->setValue(0);
        m_progressBar->setVisible(true);
        
        // Kullanıcıya işlemin başladığını bildir
        m_resultsTextEdit->setHtml(tr("<p>Starting Sandbox Analysis for file: %1</p>").arg(filePath));
        
        // ScanManager üzerinden sandbox analizi başlat
        emit scanStarted(true);
        m_scanManager->performSandboxScan(filePath);
    }
    catch (const std::exception& e) {
        displayError(tr("An error occurred during Sandbox analysis: %1").arg(e.what()));
    }
}