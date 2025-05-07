#include "../Headers/ServiceStatusDialog.h"
#include "ui_servicestatusdialog.h" // Include the generated UI header
#include "../Headers/ApiManager.h"
#include "../Headers/ScanManager.h"
#include "../Headers/DockerUIManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QPushButton>
#include <QTabWidget>
#include <QMessageBox>
#include <QProcess>
#include <QDebug>
#include <QScrollBar>
#include <QTimer>
#include <QJsonArray>
#include <QJsonObject>

ServiceStatusDialog::ServiceStatusDialog(ConfigManager* configManager, DockerManager* dockerManager, QWidget *parent)
    : QDialog(parent),
      ui(new Ui::ServiceStatusDialog), // Initialize the UI class
      appConfigManager(configManager),
      appDockerManager(dockerManager)
{
    ui->setupUi(this); // Set up the UI for this dialog

    applyStyling();
    setupConnections();

    timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &ServiceStatusDialog::updateStatus);
    timer->start(5000); // Update every 5 seconds

    updateStatus(); // Initial update
    updateDockerInfo(); // Initial Docker info update
}

ServiceStatusDialog::~ServiceStatusDialog() {
    delete ui; // Clean up the UI
}

void ServiceStatusDialog::applyStyling() {
    // Styles are now primarily in the .ui file's stylesheet property.
    // You can add or override styles here if needed.
    // For example, to set a fixed size for the icon label if not set in .ui
    // ui->iconLabel->setFixedSize(32, 32); 

    // Ensure table headers are stretched
    ui->statusTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->containerTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    // Style scroll bars (if not covered by the global stylesheet in .ui)
    QString scrollBarStyle = R"(
        QScrollBar:vertical {
            border: 1px solid #2d2d30;
            background: #1e1e1e;
            width: 15px;
            margin: 15px 0 15px 0;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: #555555;
            min-height: 20px;
            border-radius: 4px;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            border: none;
            background: none;
        }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
            background: none;
        }
    )";
    ui->statusTable->verticalScrollBar()->setStyleSheet(scrollBarStyle);
    ui->containerTable->verticalScrollBar()->setStyleSheet(scrollBarStyle);
}

void ServiceStatusDialog::setupConnections() {
    connect(ui->refreshButton, &QPushButton::clicked, this, &ServiceStatusDialog::refreshAllData);
    // The close button connection is already made in the .ui file via signals/slots editor.
    // connect(ui->closeButton, &QPushButton::clicked, this, &QDialog::accept);
}

void ServiceStatusDialog::updateStatus() {
    populateServiceStatus();
    // Docker info is updated separately as it might be more resource-intensive
}

void ServiceStatusDialog::updateDockerInfo() {
    QJsonArray containersArray = appDockerManager->listContainers(true); // Get all containers
    int totalContainers = containersArray.size();
    int runningContainers = 0;
    for (const QJsonValue& val : containersArray) {
        QJsonObject obj = val.toObject();
        // Use lowercase "status" and "state" as provided by DockerManager
        if (obj.contains("state") && obj["state"].toString().toLower() == "running") {
            runningContainers++;
        } else if (obj.contains("status") && obj["status"].toString().startsWith("Up", Qt::CaseInsensitive)) {
            runningContainers++;
        }
    }
    QJsonArray imagesArray = appDockerManager->listImages(); // Assuming a new method listImages()
    int imagesCount = imagesArray.size();
    updateDockerStatCards(runningContainers, totalContainers, imagesCount);
    populateDockerContainers(); // Refresh the table
}

void ServiceStatusDialog::refreshAllData(){
    updateStatus();
    updateDockerInfo(); // This already calls populateDockerContainers
}

void ServiceStatusDialog::populateServiceStatus() {
    ui->statusTable->setRowCount(0); // Clear existing rows
    ui->statusTable->setColumnCount(3);
    ui->statusTable->setHorizontalHeaderLabels({"Service", "Status", "Details"});

    QList<ServiceStatus> services = appConfigManager->checkServiceStatus(); // Use the new method

    for (const auto& service : services) {
        int row = ui->statusTable->rowCount();
        ui->statusTable->insertRow(row);

        QTableWidgetItem *nameItem = new QTableWidgetItem(service.name);
        QTableWidgetItem *statusItem = new QTableWidgetItem(service.status);
        QTableWidgetItem *detailsItem = new QTableWidgetItem(service.details);

        nameItem->setForeground(QBrush(QColor("#e0e0e0")));
        detailsItem->setForeground(QBrush(QColor("#b0b0b0")));

        if (service.status.contains("Active", Qt::CaseInsensitive)) { // Changed to Active for consistency
            statusItem->setForeground(QBrush(QColor("#4CAF50"))); // Green
        } else {
            statusItem->setForeground(QBrush(QColor("#F44336"))); // Red
        }

        ui->statusTable->setItem(row, 0, nameItem);
        ui->statusTable->setItem(row, 1, statusItem);
        ui->statusTable->setItem(row, 2, detailsItem);
    }

    ui->statusTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    ui->statusTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->statusTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
}

void ServiceStatusDialog::populateDockerContainers() {
    ui->containerTable->setRowCount(0); // Clear existing rows
    ui->containerTable->setColumnCount(5);
    ui->containerTable->setHorizontalHeaderLabels({"Name", "ID", "Image", "Status", "Ports"});

    QJsonArray containers = appDockerManager->listContainers(true); // Get all containers to show in table

    for (const QJsonValue& val : containers) {
        QJsonObject container = val.toObject();
        int row = ui->containerTable->rowCount();
        ui->containerTable->insertRow(row);

        // Use lowercase keys as provided by DockerManager::listContainers()
        QString name = container.contains("name") ? container["name"].toString() : "N/A";
        QString id = container.contains("id") ? container["id"].toString().left(12) : "N/A"; // Use "id"
        QString image = container.contains("image") ? container["image"].toString() : "N/A"; // Use "image"
        QString status = container.contains("status") ? container["status"].toString() : "N/A"; // Use "status"
        QString ports_str = container.contains("ports") ? container["ports"].toString() : "N/A"; // Use "ports"

        QTableWidgetItem *nameItem = new QTableWidgetItem(name);
        QTableWidgetItem *idItem = new QTableWidgetItem(id);
        QTableWidgetItem *imageItem = new QTableWidgetItem(image);
        QTableWidgetItem *statusItem = new QTableWidgetItem(status);
        QTableWidgetItem *portsItem = new QTableWidgetItem(ports_str);

        nameItem->setForeground(QBrush(QColor("#e0e0e0")));
        idItem->setForeground(QBrush(QColor("#b0b0b0")));
        imageItem->setForeground(QBrush(QColor("#b0b0b0")));
        portsItem->setForeground(QBrush(QColor("#b0b0b0")));

        if (status.contains("Up", Qt::CaseInsensitive) || status.contains("running", Qt::CaseInsensitive)) {
            statusItem->setForeground(QBrush(QColor("#4CAF50"))); // Green
        } else {
            statusItem->setForeground(QBrush(QColor("#FF9800"))); // Orange for non-running but not error
        }

        ui->containerTable->setItem(row, 0, nameItem);
        ui->containerTable->setItem(row, 1, idItem);
        ui->containerTable->setItem(row, 2, imageItem);
        ui->containerTable->setItem(row, 3, statusItem);
        ui->containerTable->setItem(row, 4, portsItem);
    }
    ui->containerTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

void ServiceStatusDialog::updateDockerStatCards(int running, int total, int images) {
    ui->runningContainerValueLabel->setText(QString::number(running));
    ui->totalContainerValueLabel->setText(QString::number(total));
    ui->imageValueLabel->setText(QString::number(images));
}
