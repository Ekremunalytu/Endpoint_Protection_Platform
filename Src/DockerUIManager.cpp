#include "../Headers/DockerUIManager.h"
#include "../Headers/Interfaces/IDockerManager.h" // IDockerManager arayüzünü dahil et
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QDateTime>
#include <QProcess>

DockerUIManager::DockerUIManager(QObject *parent)
    : QObject(parent),
      m_containerTableWidget(nullptr),
      m_logTextEdit(nullptr),
      m_dockerManager(nullptr) // DockerManager'ı oluşturmak yerine başlangıçta nullptr atıyoruz
{
    // Artık m_dockerManager'ı dışarıdan setDockerManager metodu ile ayarlayacağız
}

DockerUIManager::~DockerUIManager()
{
    // DockerManager parent'a sahip olduğu için burada silmeye gerek yok
}

// Docker manager'ı ayarlama metodu
void DockerUIManager::setDockerManager(IDockerManager* dockerManager)
{
    m_dockerManager = dockerManager;
}

void DockerUIManager::setTableWidget(QTableWidget* tableWidget)
{
    m_containerTableWidget = tableWidget;
}

void DockerUIManager::setLogTextEdit(QPlainTextEdit* logTextEdit)
{
    m_logTextEdit = logTextEdit;
}

bool DockerUIManager::isDockerAvailable() const
{
    // Docker manager null kontrolü ekleyelim
    if (!m_dockerManager) {
        return false;
    }
    return m_dockerManager->isDockerAvailable();
}

void DockerUIManager::showContainerDetails()
{
    // Create a dialog to display Docker container details
    QDialog *containerDialog = new QDialog();
    containerDialog->setWindowTitle("Docker Container Details");
    containerDialog->setMinimumSize(800, 600); // Increased size
    containerDialog->resize(1000, 700); // Larger default size
    
    QVBoxLayout *layout = new QVBoxLayout(containerDialog);
    layout->setSpacing(10);
    layout->setContentsMargins(15, 15, 15, 15);
    
    // Container table
    QTableWidget *containerTableWidget = new QTableWidget(containerDialog);
    containerTableWidget->setColumnCount(5);
    containerTableWidget->setHorizontalHeaderLabels(QStringList() << "ID" << "Name" << "Image" << "Status" << "Ports");
    containerTableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    containerTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    containerTableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    containerTableWidget->setAlternatingRowColors(true);
    // Stil tanımlamasını kaldırıp objectName ekledik
    
    layout->addWidget(containerTableWidget);
    
    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    
    QPushButton *refreshButton = new QPushButton("Refresh", containerDialog);
    // Stil tanımlamasını değiştirip normal QPushButton kullanıyoruz
    
    QPushButton *closeButton = new QPushButton("Close", containerDialog);
    closeButton->setObjectName("dangerButton");
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(refreshButton);
    buttonLayout->addWidget(closeButton);
    
    layout->addLayout(buttonLayout);
    
    // Show first container list
    setTableWidget(containerTableWidget);
    updateContainerList();
    
    // Button connections
    QObject::connect(refreshButton, &QPushButton::clicked, this, &DockerUIManager::updateContainerList);
    QObject::connect(closeButton, &QPushButton::clicked, containerDialog, &QDialog::accept);
    
    // Check current Docker status - Only add log, don't display status (specific to Service Status page)
    if (isDockerAvailable() && m_logTextEdit) {
        // Add Docker status to log section
        m_logTextEdit->appendPlainText(QString("\n🔍 %1 | Docker status checked: Available")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
    } else if (m_logTextEdit) {
        m_logTextEdit->appendPlainText(QString("\n⚠️ %1 | Docker is not available or not running!")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
    }
    
    containerDialog->exec();
    delete containerDialog;
}

void DockerUIManager::updateContainerList()
{
    if (!m_containerTableWidget || !m_dockerManager) return;
    
    m_containerTableWidget->setRowCount(0);
    
    if (!isDockerAvailable()) {
        QTableWidgetItem *errorItem = new QTableWidgetItem("Docker is not available or not running!");
        m_containerTableWidget->insertRow(0);
        m_containerTableWidget->setSpan(0, 0, 1, 5);
        m_containerTableWidget->setItem(0, 0, errorItem);
        return;
    }
    
    // listContainers yerine getDockerContainers kullanılıyor
    QJsonArray containers = m_dockerManager->getDockerContainers();
    
    for (int i = 0; i < containers.size(); ++i) {
        QJsonObject container = containers[i].toObject();
        
        int row = m_containerTableWidget->rowCount();
        m_containerTableWidget->insertRow(row);
        
        // Add container information to the table
        m_containerTableWidget->setItem(row, 0, new QTableWidgetItem(container["id"].toString()));
        m_containerTableWidget->setItem(row, 1, new QTableWidgetItem(container["name"].toString()));
        m_containerTableWidget->setItem(row, 2, new QTableWidgetItem(container["image"].toString()));
        m_containerTableWidget->setItem(row, 3, new QTableWidgetItem(container["status"].toString()));
        m_containerTableWidget->setItem(row, 4, new QTableWidgetItem(container["ports"].toString()));
        
        // If this is the active container (used by our application), change its color
        if (container["current"].toBool()) {
            for (int col = 0; col < m_containerTableWidget->columnCount(); ++col) {
                QTableWidgetItem *item = m_containerTableWidget->item(row, col);
                if (item) {
                    item->setBackground(QColor(0, 100, 0, 100)); // Dark green background
                    item->setForeground(Qt::white); // White text
                }
            }
        }
    }
}

QJsonArray DockerUIManager::getDockerContainers()
{
    // List containers through the DockerManager class
    if (!m_dockerManager || !isDockerAvailable()) {
        return QJsonArray(); // Return empty list if Docker is not running
    }
    
    // IDockerManager arayüzündeki uygun metodu kullan
    return m_dockerManager->getDockerContainers();
}

QJsonArray DockerUIManager::getDockerImages()
{
    // List images through the DockerManager class
    if (!m_dockerManager || !isDockerAvailable()) {
        return QJsonArray(); // Return empty list if Docker is not running
    }
    
    // IDockerManager arayüzündeki uygun metodu kullan
    return m_dockerManager->getDockerImages();
}