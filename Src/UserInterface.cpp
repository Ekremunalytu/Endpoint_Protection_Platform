#include "../Headers/UserInterface.h"
#include "../Headers/HashCalculation.h"
#include "../Headers/DbManager.h"

#include <QAction>
#include <QFileDialog>
#include <QMessageBox>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    // Adım 1: Aksiyonları oluştur
    createActions();
    // Adım 2: Menüleri oluştur
    createMenus();
    // Adım 3: Araç çubuklarını oluştur
    createToolBars();
    // Adım 4: Status bar (durum çubuğu) oluştur
    createStatusBar();

    // Ana pencerenin merkezine basit bir widget yerleştiriyoruz
    QWidget *widget = new QWidget;
    setCentralWidget(widget);

    // Bu widget içinde bir dikey layout
    QVBoxLayout *layout = new QVBoxLayout(widget);

    // Durum etiketini layout’a ekleyelim
    statusLabel = new QLabel(tr("Durum: Hazır"), this);
    layout->addWidget(statusLabel);

    // Pencere başlığı
    setWindowTitle(tr("Antivirüs Programı - Windows 11"));

    // Tam ekran açmak isterseniz:
    // showFullScreen();
    // veya sadece maksimum boyutta açmak isterseniz:
    // showMaximized();
}

MainWindow::~MainWindow()
{
}

// -- Aksiyonları oluşturma --
void MainWindow::createActions()
{
    // Tarama Yap
    scanAction = new QAction(tr("Tarama Yap"), this);
    connect(scanAction, &QAction::triggered, this, &MainWindow::onScanButtonClicked);

    // Güncelle
    updateAction = new QAction(tr("Güncelle"), this);
    connect(updateAction, &QAction::triggered, this, &MainWindow::onUpdateButtonClicked);

    // Virustotal Scan
    virusTotalAction = new QAction(tr("Virustotal scan"), this);
    connect(virusTotalAction, &QAction::triggered, this, &MainWindow::onsendVirusTotalButtonClicked);
}

// -- Menüleri oluşturma --
void MainWindow::createMenus()
{
    // Ana menü çubuğu (QMainWindow::menuBar() ile otomatik oluşturulur)
    // "Özellikler" menüsü ekleyelim
    featureMenu = menuBar()->addMenu(tr("Özellikler"));

    // Menüye aksiyonları ekliyoruz
    featureMenu->addAction(scanAction);
    featureMenu->addAction(updateAction);
    featureMenu->addAction(virusTotalAction);
}

// -- Araç çubuklarını (toolbars) oluşturma --
void MainWindow::createToolBars()
{
    // "Özellikler" araç çubuğu ekleyelim
    featureToolBar = addToolBar(tr("Özellikler"));
    featureToolBar->addAction(scanAction);
    featureToolBar->addAction(updateAction);
    featureToolBar->addAction(virusTotalAction);
}

// -- Status bar oluşturma --
void MainWindow::createStatusBar()
{
    // QMainWindow’un kendi statusBar() fonksiyonu ile erişebiliriz
    statusBar()->showMessage(tr("Hazır"));
}

// -- Tarama Yap butonu tıklandığında --
void MainWindow::onScanButtonClicked()
{
    // Dosya seçme diyaloğu
    QString filePath = QFileDialog::getOpenFileName(this, tr("Dosya Seç"), QString(), tr("Tüm Dosyalar (*.*)"));
    if (filePath.isEmpty()) {
        statusLabel->setText("Dosya seçilmedi.");
        return;
    }
    statusLabel->setText("Dosya seçildi. Hash hesaplamaları yapılıyor...");

    // Hash hesaplamaları
    QString md5Hash   = HashCalculation::Md5Hashing(filePath);
    QString sha1Hash  = HashCalculation::Sha1Hashing(filePath);
    QString sha256Hash= HashCalculation::Sha256Hashing(filePath);

    // Veritabanı aramaları
    QString md5Result    = DbManager::searchHashmMd5(md5Hash);
    QString sha1Result   = DbManager::searchHashSha_1(sha1Hash);
    QString sha256Result = DbManager::searchHashSha_256(sha256Hash);

    // Sonuçları derle
    QString resultText = QString("MD5: %1\nSHA1: %2\nSHA256: %3")
            .arg(md5Result.isEmpty() ? "Temiz" : md5Result)
            .arg(sha1Result.isEmpty() ? "Temiz" : sha1Result)
            .arg(sha256Result.isEmpty() ? "Temiz" : sha256Result);

    // Üç hash de veritabanında bulunamadıysa temizdir
    if (md5Result.isEmpty() && sha1Result.isEmpty() && sha256Result.isEmpty()) {
        resultText = "Tehdit algılanmadı. Dosya temiz.";
    }

    statusLabel->setText("Tarama tamamlandı.");
    QMessageBox::information(this, tr("Tarama Sonucu"), resultText);
}

// -- Güncelle butonu tıklandığında --
void MainWindow::onUpdateButtonClicked()
{
    statusLabel->setText("Virüs tanımları güncelleniyor...");
    // Burada güncelleme işlemleri yapılabilir
    statusLabel->setText("Güncelleme tamamlandı!");
}

// -- Virustotal Scan butonu tıklandığında --
void MainWindow::onsendVirusTotalButtonClicked()
{
    statusLabel->setText("Sending file to virustotal...");
    // Burada Virustotal entegrasyonu yapılabilir
    statusLabel->setText("File has been sent to virustotal!!");
}
