#ifndef USERINTERFACE_H
#define USERINTERFACE_H

#include <QMainWindow>
#include <QLabel>
#include <QPlainTextEdit>

class QAction;
class QMenu;
class QToolBar;

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
    void createActions();
    void createMenus();
    void createToolBars();
    void createStatusBar();
    void createCentralWidgets();

    // Menü, araç çubuğu ve aksiyonlar
    QMenu      *featureMenu;
    QToolBar   *featureToolBar;
    QAction    *scanAction;
    QAction    *updateAction;
    QAction    *virusTotalAction;

    // Ana ekranda göstereceğimiz bileşenler
    QLabel         *statusLabel;      // Altta kısa mesajlar için
    QPlainTextEdit *resultTextEdit;   // Hash sonuçlarını göstermek için
};

#endif // USERINTERFACE_H
