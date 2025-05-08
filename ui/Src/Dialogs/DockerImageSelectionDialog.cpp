#include "../../Headers/Dialogs/DockerImageSelectionDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

DockerImageSelectionDialog::DockerImageSelectionDialog(
    const QStringList& availableImages,
    const QString& currentImage,
    const QString& serviceType,
    QWidget *parent
) : QDialog(parent)
{
    // Dialog ayarları
    setWindowTitle(tr("Select Docker Image for %1").arg(serviceType));
    setModal(true);
    setMinimumSize(600, 350);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setSpacing(20);
    layout->setContentsMargins(30, 30, 30, 30);

    // Üst kısımda hizalı başlık
    QHBoxLayout* titleLayout = new QHBoxLayout();
    QLabel* iconLabel = new QLabel("🐳", this);
    iconLabel->setObjectName("dockerIconLabel");

    QLabel* titleLabel = new QLabel(tr("%1 Docker Image").arg(serviceType), this);
    titleLabel->setObjectName("dockerTitleLabel");
    
    titleLayout->addWidget(iconLabel);
    titleLayout->addWidget(titleLabel);
    titleLayout->addStretch();
    layout->addLayout(titleLayout);
    
    // Açıklama metni
    QLabel* descLabel = new QLabel(tr("Select a Docker image to use for %1 processing:").arg(serviceType), this);
    descLabel->setObjectName("dockerDescLabel");
    descLabel->setWordWrap(true);
    layout->addWidget(descLabel);

    // Docker imajları için dropdown
    imageComboBox = new QComboBox(this);
    imageComboBox->addItems(availableImages);
    imageComboBox->setMinimumHeight(50);
    
    // Mevcut imaj seçili gelsin
    int currentIndex = availableImages.indexOf(currentImage);
    if (currentIndex >= 0) {
        imageComboBox->setCurrentIndex(currentIndex);
    }
    
    layout->addWidget(imageComboBox);
    
    // Docker Hub linki
    QLabel* hubLabel = new QLabel(tr("Don't see what you need? <a href='https://hub.docker.com/search?q=%1&type=image'>Search on Docker Hub</a>").arg(serviceType.toLower()), this);
    hubLabel->setOpenExternalLinks(true);
    hubLabel->setObjectName("dockerHubLabel");
    layout->addWidget(hubLabel);
    
    // Alt kısımda butonlar
    layout->addSpacing(20);
    
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(15);
    
    QPushButton *cancelButton = new QPushButton(tr("Cancel"), this);
    QPushButton *okButton = new QPushButton(tr("Select"), this);
    
    // Butonların minimum boyutu
    cancelButton->setMinimumSize(150, 45);
    okButton->setMinimumSize(150, 45);
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(okButton);
    
    layout->addLayout(buttonLayout);
    
    // Bağlantılar
    connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
}

QString DockerImageSelectionDialog::getSelectedImage() const {
    return imageComboBox->currentText();
}