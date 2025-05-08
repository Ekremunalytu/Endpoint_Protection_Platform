#include "Dialogs/ServiceStatusDialog.h" // Corrected include path
#include "Interfaces/Headers/IApiManager.h"
#include "ScanManager.h"
#include "DockerUIManager.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QMessageBox>
#include <QJsonObject>
#include <QJsonArray>
#include <QDateTime>

ServiceStatusDialog::ServiceStatusDialog(IApiManager* apiManager, ScanManager* scanManager, DockerUIManager* dockerUIManager, QWidget* parent)
    : QDialog(parent),
      m_apiManager(apiManager),
      m_scanManager(scanManager),
      m_dockerUIManager(dockerUIManager),
      m_tabWidget(nullptr),
      m_statusTable(nullptr),
      m_containerTable(nullptr),
      m_runningContainerValue(nullptr),
      m_totalContainerValue(nullptr),
      m_imageValue(nullptr),
      m_refreshButton(nullptr)
{
    // Null pointer kontrolleri
    if (!m_apiManager || !m_scanManager || !m_dockerUIManager) {
        throw std::runtime_error("ServiceStatusDialog: Null pointers provided");
    }

    setWindowTitle(tr("Service Status"));
    setMinimumSize(800, 600);
    createUI();
    updateServiceStatus();
    setupConnections();
}

void ServiceStatusDialog::createUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(20);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    // Tab widget
    m_tabWidget = new QTabWidget(this);
    m_tabWidget->setObjectName("statusTabWidget");

    // Servis durumları sekmesi
    QWidget* servicesTab = new QWidget(m_tabWidget);
    QVBoxLayout* servicesLayout = new QVBoxLayout(servicesTab);
    servicesLayout->setSpacing(20);
    servicesLayout->setContentsMargins(20, 20, 20, 20);

    // Servis durumu tablosu
    m_statusTable = new QTableWidget(servicesTab);
    m_statusTable->setColumnCount(3); // Servis, Durum, Detaylar
    m_statusTable->setHorizontalHeaderLabels(QStringList() << tr("Service") << tr("Status") << tr("Details"));
    m_statusTable->horizontalHeader()->setStretchLastSection(true);
    m_statusTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_statusTable->setEditTriggers(QTableWidget::NoEditTriggers);
    m_statusTable->setSelectionBehavior(QTableWidget::SelectRows);
    m_statusTable->setAlternatingRowColors(true);
    
    servicesLayout->addWidget(m_statusTable, 1);

    // Docker konteyner sekmesi
    QWidget* dockerTab = new QWidget(m_tabWidget);
    QVBoxLayout* dockerLayout = new QVBoxLayout(dockerTab);
    dockerLayout->setSpacing(20);
    dockerLayout->setContentsMargins(20, 20, 20, 20);

    // Docker özeti
    QGroupBox* dockerSummaryGroup = new QGroupBox(tr("Docker Summary"), dockerTab);
    QGridLayout* summaryLayout = new QGridLayout(dockerSummaryGroup);
    summaryLayout->setSpacing(12);
    
    // Running containers
    QLabel* runningContainerLabel = new QLabel(tr("Running Containers:"), dockerSummaryGroup);
    m_runningContainerValue = new QLabel("0", dockerSummaryGroup);
    m_runningContainerValue->setObjectName("valueLabel");
    summaryLayout->addWidget(runningContainerLabel, 0, 0);
    summaryLayout->addWidget(m_runningContainerValue, 0, 1);
    
    // Total containers
    QLabel* totalContainerLabel = new QLabel(tr("Total Containers:"), dockerSummaryGroup);
    m_totalContainerValue = new QLabel("0", dockerSummaryGroup);
    m_totalContainerValue->setObjectName("valueLabel");
    summaryLayout->addWidget(totalContainerLabel, 1, 0);
    summaryLayout->addWidget(m_totalContainerValue, 1, 1);
    
    // Docker image
    QLabel* imageLabel = new QLabel(tr("Available Images:"), dockerSummaryGroup);
    m_imageValue = new QLabel("0", dockerSummaryGroup);
    m_imageValue->setObjectName("valueLabel");
    summaryLayout->addWidget(imageLabel, 2, 0);
    summaryLayout->addWidget(m_imageValue, 2, 1);

    // Add summary group to layout
    dockerLayout->addWidget(dockerSummaryGroup);

    // Docker containers table
    m_containerTable = new QTableWidget(dockerTab);
    m_containerTable->setColumnCount(5); // ID, Name, Image, Status, Created
    m_containerTable->setHorizontalHeaderLabels(QStringList() << tr("Container ID") << tr("Name") << tr("Image") << tr("Status") << tr("Created"));
    m_containerTable->horizontalHeader()->setStretchLastSection(true);
    m_containerTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_containerTable->setEditTriggers(QTableWidget::NoEditTriggers);
    m_containerTable->setSelectionBehavior(QTableWidget::SelectRows);
    m_containerTable->setAlternatingRowColors(true);
    
    dockerLayout->addWidget(m_containerTable, 1);

    // Add tabs
    m_tabWidget->addTab(servicesTab, tr("Services"));
    m_tabWidget->addTab(dockerTab, tr("Docker"));

    mainLayout->addWidget(m_tabWidget, 1);

    // Refresh and close buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    
    m_refreshButton = new QPushButton(tr("Refresh"), this);
    QPushButton* closeButton = new QPushButton(tr("Close"), this);
    
    buttonLayout->addWidget(m_refreshButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(closeButton);
    
    mainLayout->addLayout(buttonLayout);

    // Connections
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        updateServiceStatus();
        updateContainerList();
    });
}

void ServiceStatusDialog::updateServiceStatus()
{
    // Servis durumu tablosunu temizle
    m_statusTable->setRowCount(0);

    try {
        // VirusTotal API durumu
        int row = m_statusTable->rowCount();
        m_statusTable->insertRow(row);
        m_statusTable->setItem(row, 0, new QTableWidgetItem("VirusTotal API"));
        
        if (m_apiManager->hasApiKey()) {
            m_statusTable->setItem(row, 1, new QTableWidgetItem("✅ Available"));
            m_statusTable->setItem(row, 2, new QTableWidgetItem(tr("API key is set")));
        } else {
            m_statusTable->setItem(row, 1, new QTableWidgetItem("❌ Not Available"));
            m_statusTable->setItem(row, 2, new QTableWidgetItem(tr("API key is not set")));
        }
        
        // Offline tarama durumu (YARA)
        row = m_statusTable->rowCount();
        m_statusTable->insertRow(row);
        m_statusTable->setItem(row, 0, new QTableWidgetItem("Offline Scanning"));
        
        if (m_scanManager->isDbInitialized()) {
            m_statusTable->setItem(row, 1, new QTableWidgetItem("✅ Available"));
            m_statusTable->setItem(row, 2, new QTableWidgetItem(tr("YARA rules loaded")));
        } else {
            m_statusTable->setItem(row, 1, new QTableWidgetItem("❌ Not Available"));
            m_statusTable->setItem(row, 2, new QTableWidgetItem(tr("YARA rules not loaded")));
        }
        
        // Docker durumu
        row = m_statusTable->rowCount();
        m_statusTable->insertRow(row);
        m_statusTable->setItem(row, 0, new QTableWidgetItem("Docker"));
        
        if (m_dockerUIManager->isDockerAvailable()) {
            m_statusTable->setItem(row, 1, new QTableWidgetItem("✅ Available"));
            m_statusTable->setItem(row, 2, new QTableWidgetItem(tr("Docker is running")));
        } else {
            m_statusTable->setItem(row, 1, new QTableWidgetItem("❌ Not Available"));
            m_statusTable->setItem(row, 2, new QTableWidgetItem(tr("Docker is not running")));
        }
        
        // CDR servisi durumu
        row = m_statusTable->rowCount();
        m_statusTable->insertRow(row);
        m_statusTable->setItem(row, 0, new QTableWidgetItem("CDR Service"));
        
        const QString cdrImageName = m_scanManager->getCurrentCdrImageName();
        if (!cdrImageName.isEmpty() && m_dockerUIManager->isDockerAvailable()) {
            m_statusTable->setItem(row, 1, new QTableWidgetItem("✅ Available"));
            m_statusTable->setItem(row, 2, new QTableWidgetItem(tr("Using image: %1").arg(cdrImageName)));
        } else {
            m_statusTable->setItem(row, 1, new QTableWidgetItem("❌ Not Available"));
            m_statusTable->setItem(row, 2, new QTableWidgetItem(tr("No CDR image available")));
        }
        
        // Sandbox servisi durumu
        row = m_statusTable->rowCount();
        m_statusTable->insertRow(row);
        m_statusTable->setItem(row, 0, new QTableWidgetItem("Sandbox Service"));
        
        const QString sandboxImageName = m_scanManager->getCurrentSandboxImageName();
        if (!sandboxImageName.isEmpty() && m_dockerUIManager->isDockerAvailable()) {
            m_statusTable->setItem(row, 1, new QTableWidgetItem("✅ Available"));
            m_statusTable->setItem(row, 2, new QTableWidgetItem(tr("Using image: %1").arg(sandboxImageName)));
        } else {
            m_statusTable->setItem(row, 1, new QTableWidgetItem("❌ Not Available"));
            m_statusTable->setItem(row, 2, new QTableWidgetItem(tr("No Sandbox image available")));
        }
        
        // Docker konteyner listesini güncelle
        updateContainerList();
        
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Error"), 
                           tr("An error occurred while updating service status: %1").arg(e.what()));
    } catch (...) {
        QMessageBox::warning(this, tr("Error"), 
                           tr("An unknown error occurred while updating service status."));
    }
}

void ServiceStatusDialog::updateContainerList()
{
    // Konteyner tablosunu temizle
    m_containerTable->setRowCount(0);
    
    try {
        if (!m_dockerUIManager->isDockerAvailable()) {
            m_runningContainerValue->setText("0");
            m_totalContainerValue->setText("0");
            m_imageValue->setText("0");
            return;
        }
        
        // Docker konteyner listesini al
        QJsonArray containers = m_dockerUIManager->getDockerContainers();
        
        // Docker image sayısını al
        QJsonArray images = m_dockerUIManager->getDockerImages();
        m_imageValue->setText(QString::number(images.size()));
        
        // Konteyner sayılarını ayarla
        int runningContainers = 0;
        for (int i = 0; i < containers.size(); ++i) {
            QJsonObject container = containers[i].toObject();
            QString status = container["Status"].toString();
            if (status.contains("Up", Qt::CaseInsensitive)) {
                runningContainers++;
            }
        }
        
        m_runningContainerValue->setText(QString::number(runningContainers));
        m_totalContainerValue->setText(QString::number(containers.size()));
        
        // Konteynerleri tabloya ekle
        for (int i = 0; i < containers.size(); ++i) {
            QJsonObject container = containers[i].toObject();
            
            int row = m_containerTable->rowCount();
            m_containerTable->insertRow(row);
            
            QString id = container["Id"].toString();
            if (id.length() > 12) {
                id = id.left(12); // Kısa ID göster
            }
            
            m_containerTable->setItem(row, 0, new QTableWidgetItem(id));
            m_containerTable->setItem(row, 1, new QTableWidgetItem(container["Names"].toString()));
            m_containerTable->setItem(row, 2, new QTableWidgetItem(container["Image"].toString()));
            m_containerTable->setItem(row, 3, new QTableWidgetItem(container["Status"].toString()));
            
            // Unix timestamp to date
            qint64 created = container["Created"].toString().toLongLong();
            QDateTime createdDate = QDateTime::fromSecsSinceEpoch(created);
            m_containerTable->setItem(row, 4, new QTableWidgetItem(createdDate.toString("yyyy-MM-dd hh:mm:ss")));
        }
        
        // Genişlikleri ayarla
        m_containerTable->resizeColumnsToContents();
        
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Error"), 
                           tr("An error occurred while updating container list: %1").arg(e.what()));
    } catch (...) {
        QMessageBox::warning(this, tr("Error"), 
                           tr("An unknown error occurred while updating container list."));
    }
}

void ServiceStatusDialog::setupConnections()
{
    // Docker tabına geçildiğinde otomatik refresh
    connect(m_tabWidget, &QTabWidget::currentChanged, this, [this](int index) {
        if (index == 1) { // Docker tab
            updateContainerList();
        }
    });
}