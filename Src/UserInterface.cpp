#include "../Headers/UserInterface.h"
#include <QVBoxLayout>  // Layout düzeni için

// Yapıcı fonksiyon: Arayüz elemanları oluşturulur ve yapılandırılır.
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    // UI bileşenlerini oluştur ve yapılandır
    initializeUI();

    // Butonlar ve diğer etkileşimli elemanlar için sinyal-slot bağlantılarını kur.
    connectSignals();
}

// Yıkıcı fonksiyon: Qt'de parent-child ilişkisi sayesinde çoğu widget otomatik temizlenir.
// Eğer özel dinamik bellek yönetimi yapıyorsanız burada ilave temizleme kodları eklenebilir.
MainWindow::~MainWindow() {
    // Gerekirse manuel kaynak temizliği yapılır.
}

// initializeUI() fonksiyonu, tüm arayüz elemanlarını oluşturur ve layout düzenine yerleştirir.
void MainWindow::initializeUI() {
    // Ana pencerenin merkezi widget'ını oluştur
    centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Ana düzen (layout) oluştur ve merkezi widget'a uygula
    mainLayout = new QVBoxLayout(centralWidget);

    // Durum etiketini oluştur; başlangıçta "Durum: Hazır" mesajı gösterilir.
    statusLabel = new QLabel("Durum: Hazır", this);
    mainLayout->addWidget(statusLabel);

    // Tarama başlatma butonunu oluştur ve layout'a ekle.
    scanButton = new QPushButton("Tarama Yap", this);
    mainLayout->addWidget(scanButton);

    // Güncelleme butonunu oluştur ve layout'a ekle.
    updateButton = new QPushButton("Güncelle", this);
    mainLayout->addWidget(updateButton);

    // Pencere başlığını ve başlangıç boyutlarını ayarla.
    setWindowTitle("Antivirüs Programı - Windows 11");
    resize(400, 300);
}

// connectSignals() fonksiyonu, UI elemanlarının sinyal ve slot bağlantılarını gerçekleştirir.
void MainWindow::connectSignals() {
    // Tarama butonuna tıklama sinyalini onScanButtonClicked slotuna bağla.
    connect(scanButton, &QPushButton::clicked, this, &MainWindow::onScanButtonClicked);

    // Güncelle butonuna tıklama sinyalini onUpdateButtonClicked slotuna bağla.
    connect(updateButton, &QPushButton::clicked, this, &MainWindow::onUpdateButtonClicked);
}

// onScanButtonClicked() slotu, tarama işlemi başlatıldığında çağrılır.
void MainWindow::onScanButtonClicked() {
    // Durum etiketini güncelle: Tarama işlemi başladı.
    statusLabel->setText("Tarama yapılıyor...");

    // TODO: Buraya antivirüs tarama işlemlerinizin kodlarını ekleyin.
    // Örneğin, dosya tarama, virüs kontrolü gibi işlemler burada gerçekleşebilir.

    // İşlem tamamlandığında durumu güncelle.
    statusLabel->setText("Tarama tamamlandı!");
}

// onUpdateButtonClicked() slotu, güncelleme işlemi başlatıldığında çağrılır.
void MainWindow::onUpdateButtonClicked() {
    // Durum etiketini güncelle: Güncelleme işlemi başladı.
    statusLabel->setText("Virüs tanımları güncelleniyor...");

    // TODO: Buraya antivirüs güncelleme işlemlerinizin kodlarını ekleyin.
    // Örneğin, sunucudan güncel virüs tanımları çekme işlemi burada yapılabilir.

    // İşlem tamamlandığında durumu güncelle.
    statusLabel->setText("Güncelleme tamamlandı!");
}
