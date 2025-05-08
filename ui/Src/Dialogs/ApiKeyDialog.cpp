#include "../../Headers/Dialogs/ApiKeyDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

ApiKeyDialog::ApiKeyDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle(tr("API Key Settings"));
    setModal(true);
    setMinimumWidth(450);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setSpacing(20);
    layout->setContentsMargins(30, 30, 30, 30);

    QLabel *infoLabel = new QLabel(tr("Enter your VirusTotal API key:"), this);
    infoLabel->setObjectName("infoLabel");
    layout->addWidget(infoLabel);

    apiKeyLineEdit = new QLineEdit(this);
    apiKeyLineEdit->setPlaceholderText(tr("API Key here..."));
    layout->addWidget(apiKeyLineEdit);
    
    QLabel *apiInfoLabel = new QLabel(tr("Get your free API key from <a href='https://www.virustotal.com/gui/join-us'>VirusTotal</a>"), this);
    apiInfoLabel->setOpenExternalLinks(true);
    apiInfoLabel->setObjectName("apiInfoLabel");
    layout->addWidget(apiInfoLabel);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(15);

    QPushButton *okButton = new QPushButton(tr("Save"), this);
    QPushButton *cancelButton = new QPushButton(tr("Cancel"), this);

    cancelButton->setObjectName("secondaryButton");

    buttonLayout->addStretch();
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(okButton);

    layout->addSpacing(20);
    layout->addLayout(buttonLayout);

    connect(okButton, &QPushButton::clicked, this, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
}