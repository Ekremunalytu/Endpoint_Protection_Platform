\
#include "../Headers/DockerImageSelectionDialog.h"
#include "ui_dockerimageselectiondialog.h" // Assuming the .ui file is named this
#include "../Headers/DockerManager.h" // To list Docker images
#include <QJsonArray>
#include <QJsonObject>
#include <QDebug>

DockerImageSelectionDialog::DockerImageSelectionDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DockerImageSelectionDialog)
{
    ui->setupUi(this);
    populateImageList();
    connect(ui->okButton, &QPushButton::clicked, this, &DockerImageSelectionDialog::on_okButton_clicked);
    connect(ui->cancelButton, &QPushButton::clicked, this, &DockerImageSelectionDialog::on_cancelButton_clicked);
    connect(ui->imageListWidget, &QListWidget::itemDoubleClicked, this, &DockerImageSelectionDialog::on_imageListWidget_itemDoubleClicked);
}

DockerImageSelectionDialog::~DockerImageSelectionDialog()
{
    delete ui;
}

void DockerImageSelectionDialog::populateImageList()
{
    DockerManager dockerManager; // Temporary local manager, or pass one in
    QJsonArray images = dockerManager.listImages();
    ui->imageListWidget->clear();
    for (const QJsonValue &value : images)
    {
        QJsonObject image = value.toObject();
        QString imageName = image["repository"].toString() + ":" + image["tag"].toString();
        QString imageId = image["id"].toString();
        QListWidgetItem *item = new QListWidgetItem(imageName + " (ID: " + imageId.left(12) + ")");
        item->setData(Qt::UserRole, imageId); // Store full ID in item's data
        ui->imageListWidget->addItem(item);
    }
}

QString DockerImageSelectionDialog::getSelectedImageId() const
{
    return selectedImageId;
}

void DockerImageSelectionDialog::on_imageListWidget_itemDoubleClicked(QListWidgetItem *item)
{
    if (item)
    {
        selectedImageId = item->data(Qt::UserRole).toString();
        accept(); // Close dialog and return QDialog::Accepted
    }
}

void DockerImageSelectionDialog::on_okButton_clicked()
{
    QListWidgetItem *currentItem = ui->imageListWidget->currentItem();
    if (currentItem)
    {
        selectedImageId = currentItem->data(Qt::UserRole).toString();
        accept();
    }
    else
    {
        // Optionally, show a message to select an item
        qDebug() << "No image selected.";
    }
}

void DockerImageSelectionDialog::on_cancelButton_clicked()
{
    reject(); // Close dialog and return QDialog::Rejected
}
