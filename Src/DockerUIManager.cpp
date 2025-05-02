#include "../Headers/DockerUIManager.h"
#include "../Headers/DockerManager.h"
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QDateTime>

DockerUIManager::DockerUIManager(QObject *parent)
    : QObject(parent),
      m_containerTableWidget(nullptr),
      m_logTextEdit(nullptr)
{
    m_dockerManager = new DockerManager(this);
}

DockerUIManager::~DockerUIManager()
{
    // DockerManager parent'a sahip olduğu için burada silmeye gerek yok
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
    return m_dockerManager->isDockerAvailable();
}

void DockerUIManager::showContainerDetails()
{
    // Docker konteyner detaylarını gösteren bir dialog oluştur
    QDialog *containerDialog = new QDialog();
    containerDialog->setWindowTitle("Docker Konteyner Detayları");
    containerDialog->setMinimumSize(800, 400);
    
    QVBoxLayout *layout = new QVBoxLayout(containerDialog);
    
    // Konteyner tablosu
    QTableWidget *containerTableWidget = new QTableWidget(containerDialog);
    containerTableWidget->setColumnCount(5);
    containerTableWidget->setHorizontalHeaderLabels(QStringList() << "ID" << "İsim" << "İmaj" << "Durum" << "Portlar");
    containerTableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    containerTableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    containerTableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    containerTableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    containerTableWidget->setAlternatingRowColors(true);
    containerTableWidget->setStyleSheet(
        "QTableWidget {"
        "   background-color: #181818;"
        "   color: #cccccc;"
        "   border: 1px solid #333333;"
        "   gridline-color: #333333;"
        "}"
        "QTableWidget::item {"
        "   padding: 5px;"
        "}"
        "QTableWidget::item:selected {"
        "   background-color: #2a82da;"
        "}"
        "QHeaderView::section {"
        "   background-color: #222222;"
        "   color: white;"
        "   font-weight: bold;"
        "   border: 1px solid #333333;"
        "   padding: 4px;"
        "}"
    );
    
    layout->addWidget(containerTableWidget);
    
    // Butonlar
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    
    QPushButton *refreshButton = new QPushButton("Yenile", containerDialog);
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
    
    QPushButton *closeButton = new QPushButton("Kapat", containerDialog);
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
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(refreshButton);
    buttonLayout->addWidget(closeButton);
    
    layout->addLayout(buttonLayout);
    
    // İlk konteyner listesini göster
    setTableWidget(containerTableWidget);
    updateContainerList();
    
    // Buton bağlantıları
    QObject::connect(refreshButton, &QPushButton::clicked, this, &DockerUIManager::updateContainerList);
    QObject::connect(closeButton, &QPushButton::clicked, containerDialog, &QDialog::accept);
    
    // Mevcut Docker durumunu kontrol et
    if (m_dockerManager->isDockerAvailable() && m_logTextEdit) {
        // Docker durumunu log kısmına ekle
        m_logTextEdit->appendPlainText(QString("\n🔍 %1 | Docker durumu kontrol edildi: Mevcut")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
            
        // Docker konteyner bilgilerini al
        QJsonArray containers = m_dockerManager->listContainers();
        
        // Eğer aktif konteyner varsa bilgilerini göster
        for (int i = 0; i < containers.size(); ++i) {
            QJsonObject container = containers[i].toObject();
            if (container["current"].toBool()) {
                m_logTextEdit->appendPlainText(QString("📦 Aktif konteyner: %1 (%2)\n   Durum: %3")
                    .arg(container["name"].toString())
                    .arg(container["image"].toString())
                    .arg(container["status"].toString()));
            }
        }
    } else if (m_logTextEdit) {
        m_logTextEdit->appendPlainText(QString("\n⚠️ %1 | Docker mevcut değil veya çalışmıyor!")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
    }
    
    containerDialog->exec();
    delete containerDialog;
}

void DockerUIManager::updateContainerList()
{
    if (!m_containerTableWidget || !m_dockerManager) return;
    
    m_containerTableWidget->setRowCount(0);
    
    if (!m_dockerManager->isDockerAvailable()) {
        QTableWidgetItem *errorItem = new QTableWidgetItem("Docker mevcut değil veya çalışmıyor!");
        m_containerTableWidget->insertRow(0);
        m_containerTableWidget->setSpan(0, 0, 1, 5);
        m_containerTableWidget->setItem(0, 0, errorItem);
        return;
    }
    
    QJsonArray containers = m_dockerManager->listContainers();
    
    for (int i = 0; i < containers.size(); ++i) {
        QJsonObject container = containers[i].toObject();
        
        int row = m_containerTableWidget->rowCount();
        m_containerTableWidget->insertRow(row);
        
        // Konteyner bilgilerini tabloya ekle
        m_containerTableWidget->setItem(row, 0, new QTableWidgetItem(container["id"].toString()));
        m_containerTableWidget->setItem(row, 1, new QTableWidgetItem(container["name"].toString()));
        m_containerTableWidget->setItem(row, 2, new QTableWidgetItem(container["image"].toString()));
        m_containerTableWidget->setItem(row, 3, new QTableWidgetItem(container["status"].toString()));
        m_containerTableWidget->setItem(row, 4, new QTableWidgetItem(container["ports"].toString()));
        
        // Eğer bu aktif konteynerse (bizim uygulamamızın kullandığı) rengini değiştir
        if (container["current"].toBool()) {
            for (int col = 0; col < m_containerTableWidget->columnCount(); ++col) {
                QTableWidgetItem *item = m_containerTableWidget->item(row, col);
                if (item) {
                    item->setBackground(QColor(0, 100, 0, 100)); // Koyu yeşil arkaplan
                    item->setForeground(Qt::white); // Beyaz metin
                }
            }
        }
    }
}