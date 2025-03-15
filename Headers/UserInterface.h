#ifndef USERINTERFACE_H
#define USERINTERFACE_H

#include <QMainWindow>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QWidget>

// MainWindow sınıfı, QMainWindow sınıfından türetilmiştir.
// Bu sınıf, antivirüs programınızın ana arayüzünü oluşturur.
class MainWindow : public QMainWindow {
    Q_OBJECT  // Qt'nin sinyal-slot mekanizmasını kullanabilmek için gerekli makro

public:
    // Yapıcı fonksiyon; parent parametresi ile isteğe bağlı üst widget tanımlanır.
    explicit MainWindow(QWidget *parent = nullptr);

    // Yıkıcı fonksiyon; dinamik olarak ayrılmış kaynakların temizlenmesi için.
    ~MainWindow();

    private slots:
        // Kullanıcı "Tarama Yap" butonuna bastığında çalışacak slot.
        void onScanButtonClicked();

    // Kullanıcı "Güncelle" butonuna bastığında çalışacak slot.
    void onUpdateButtonClicked();

private:
    // Arayüz elemanlarını ve layout düzenini tanımlayan özel üye değişkenler.

    // Merkezi widget; ana pencerenin içerisine yerleştirilen temel widget.
    QWidget *centralWidget;

    // Ana düzen (layout) nesnesi; widget'ların dikey olarak sıralanmasını sağlar.
    QVBoxLayout *mainLayout;

    // Durum bilgilerini göstermek için etiket.
    QLabel *statusLabel;

    // Tarama işlemini başlatan buton.
    QPushButton *scanButton;

    // Virüs tanımları güncelleme işlemini başlatan buton.
    QPushButton *updateButton;

    // UI bileşenlerinin oluşturulması için yardımcı fonksiyon.
    void initializeUI();

    // Sinyal ve slot bağlantılarının kurulması için yardımcı fonksiyon.
    void connectSignals();
};

#endif USERINTERFACE_H
