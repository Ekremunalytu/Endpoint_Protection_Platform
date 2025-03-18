#ifndef USERINTERFACE_H
#define USERINTERFACE_H

#include <QMainWindow>
#include <QLabel>

// İleri deklarasyonlar
class QAction;
class QMenu;
class QToolBar;

// MainWindow sınıfı
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    private slots:
        void onScanButtonClicked();
    void onUpdateButtonClicked();
    void onsendVirusTotalButtonClicked();

private:
    // Menü, araç çubuğu ve aksiyonları oluşturmak için yardımcı fonksiyonlar
    void createActions();
    void createMenus();
    void createToolBars();
    void createStatusBar();

    // Arayüz bileşenleri
    QLabel *statusLabel;      // Durum etiketimiz
    QMenu *featureMenu;       // "Özellikler" menüsü
    QToolBar *featureToolBar; // "Özellikler" araç çubuğu

    // Aksiyonlar (menü maddeleri / butonlar)
    QAction *scanAction;          // "Tarama Yap"
    QAction *updateAction;        // "Güncelle"
    QAction *virusTotalAction;    // "Virustotal scan"
};

#endif // USERINTERFACE_H
