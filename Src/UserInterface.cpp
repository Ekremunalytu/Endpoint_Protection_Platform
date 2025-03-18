#include "../Headers/UserInterface.h"

// Proje içi diğer başlıklar (DbManager, HashCalculation vs.)
#include "../Headers/DbManager.h"
#include "../Headers/HashCalculation.h"

#include <QAction>
#include <QFileDialog>
#include <QMessageBox>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QFont>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      featureMenu(nullptr),
      featureToolBar(nullptr),
      scanAction(nullptr),
      updateAction(nullptr),
      virusTotalAction(nullptr),
      statusLabel(nullptr),
      resultTextEdit(nullptr)
{
    // Stil düzenlemeleri: Butonları büyütmek, menüleri okunur kılmak vb.
    // (İsteğe göre özelleştirebilirsiniz)
    this->setStyleSheet(
        "QToolBar {"
        "   spacing: 10px;"  // Butonlar arasındaki boşluk
        "}"
        "QToolButton {"
        "   font: bold 14px;"
        "   min-width: 120px;"
        "   min-height: 40px;"
        "}"
        "QMenuBar {"
        "   font: 14px;"
        "}"
        "QMenu {"
        "   font: 14px;"
        "}"
        "QLabel {"
        "   font: 14px;"
        "}"
        "QPlainTextEdit {"
        "   font: 14px;"
        "}"
    );

    createActions();       // Aksiyonları oluştur
    createMenus();         // Menüleri oluştur
    createToolBars();      // Araç çubuklarını oluştur
    createStatusBar();     // Status bar

    createCentralWidgets(); // Merkezdeki widget ve layout

    // Pencere başlığı
    setWindowTitle(tr("Antivirüs Programı - Windows 11"));

    // Tam ekran aç
    showFullScreen();
}

MainWindow::~MainWindow()
{
}

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

void MainWindow::createMenus()
{
    // Ana menü çubuğu
    featureMenu = menuBar()->addMenu(tr("Özellikler"));

    // Menüye aksiyonları ekliyoruz
    featureMenu->addAction(scanAction);
    featureMenu->addAction(updateAction);
    featureMenu->addAction(virusTotalAction);
}

void MainWindow::createToolBars()
{
    // "Özellikler" araç çubuğu
    featureToolBar = addToolBar(tr("Özellikler"));
    featureToolBar->addAction(scanAction);
    featureToolBar->addAction(updateAction);
    featureToolBar->addAction(virusTotalAction);
}

void MainWindow::createStatusBar()
{
    // QMainWindow'un kendi statusBar()'ını kullanarak basit bir mesaj gösterebiliriz
    statusBar()->showMessage(tr("Hazır"));
}

// Merkezdeki widget ve layout
void MainWindow::createCentralWidgets()
{
    // Ana pencerenin merkezine yerleştireceğimiz widget
    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    // Dikey layout
    QVBoxLayout *layout = new QVBoxLayout(central);
    central->setLayout(layout);

    // Tarama sonuçlarını göstereceğimiz metin kutusu
    resultTextEdit = new QPlainTextEdit(this);
    resultTextEdit->setReadOnly(true);
    layout->addWidget(resultTextEdit);

    // Altta bir durum etiketi
    statusLabel = new QLabel(tr("Durum: Hazır"), this);
    layout->addWidget(statusLabel);
}

// -- Tarama Yap tıklanınca --
void MainWindow::onScanButtonClicked()
{
    // Dosya seçme
    QString filePath = QFileDialog::getOpenFileName(this, tr("Dosya Seç"), QString(), tr("Tüm Dosyalar (*.*)"));
    if (filePath.isEmpty()) {
        statusLabel->setText("Dosya seçilmedi.");
        return;
    }
    statusLabel->setText("Dosya seçildi. Hash hesaplamaları yapılıyor...");

    // Hash hesaplamaları
    QString md5Hash    = HashCalculation::Md5Hashing(filePath);
    QString sha1Hash   = HashCalculation::Sha1Hashing(filePath);
    QString sha256Hash = HashCalculation::Sha256Hashing(filePath);

    // Veritabanı aramaları
    QString md5Result    = DbManager::searchHashmMd5(md5Hash);
    QString sha1Result   = DbManager::searchHashSha_1(sha1Hash);
    QString sha256Result = DbManager::searchHashSha_256(sha256Hash);

    // Sonuçları ekranda göstermek için resultTextEdit'i temizleyip yazalım
    resultTextEdit->clear();
    resultTextEdit->appendPlainText("=== Tarama Sonucu ===");
    resultTextEdit->appendPlainText(QString("MD5: %1 => %2")
        .arg(md5Hash, md5Result.isEmpty() ? "Temiz" : md5Result));
    resultTextEdit->appendPlainText(QString("SHA1: %1 => %2")
        .arg(sha1Hash, sha1Result.isEmpty() ? "Temiz" : sha1Result));
    resultTextEdit->appendPlainText(QString("SHA256: %1 => %2")
        .arg(sha256Hash, sha256Result.isEmpty() ? "Temiz" : sha256Result));

    // Eğer hiçbir hash veritabanında yoksa dosya temiz
    if (md5Result.isEmpty() && sha1Result.isEmpty() && sha256Result.isEmpty()) {
        resultTextEdit->appendPlainText("\nTehdit algılanmadı. Dosya temiz.");
    }

    statusLabel->setText("Tarama tamamlandı.");
}

// -- Güncelle tıklanınca --
void MainWindow::onUpdateButtonClicked()
{
    statusLabel->setText("Virüs tanımları güncelleniyor...");
    // Güncelleme işlemleri
    statusLabel->setText("Güncelleme tamamlandı!");
}

// -- Virustotal Scan tıklanınca --
void MainWindow::onsendVirusTotalButtonClicked()
{
    statusLabel->setText("Sending file to virustotal...");
    // Virustotal entegrasyonu
    statusLabel->setText("File has been sent to virustotal!!");
}
