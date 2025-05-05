#ifndef USERINTERFACE_H
#define USERINTERFACE_H

#include <QMainWindow>
#include <QLabel>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QDialog>
#include <QVBoxLayout>
#include <QPushButton>
#include <QToolButton>
#include <QTableWidget>
#include "ApiManager.h"
#include "ScanManager.h"
#include "ResultsView.h"
#include "DockerUIManager.h"
#include <QJsonObject>
#include <QComboBox>

/**
 * @brief Docker imaj seçim dialog'u
 */
class DockerImageSelectionDialog : public QDialog {
    Q_OBJECT
    
public:
    /**
     * @brief DockerImageSelectionDialog nesnesi oluşturur
     * @param availableImages Seçilebilecek imaj listesi
     * @param currentImage Mevcut seçili imaj
     * @param serviceType Servis tipi ("CDR" veya "Sandbox")
     * @param parent Üst widget
     */
    DockerImageSelectionDialog(const QStringList& availableImages, 
                              const QString& currentImage,
                              const QString& serviceType,
                              QWidget *parent = nullptr);
    
    /**
     * @brief Kullanıcının seçtiği imaj adını döndürür
     * @return Seçilen imaj adı
     */
    QString getSelectedImage() const;
    
private:
    QComboBox* imageComboBox;
};

// API anahtarı iletişim penceresi sınıfı
class ApiKeyDialog : public QDialog {
    Q_OBJECT
public:
    explicit ApiKeyDialog(QWidget *parent = nullptr);
    QString getApiKey() const { return apiKeyLineEdit->text(); }

private:
    QLineEdit *apiKeyLineEdit;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onScanButtonClicked();
    void onsendVirusTotalButtonClicked();
    void onApiKeyButtonClicked();
    void onCdrButtonClicked();
    void onSandboxButtonClicked();
    void onApiResponseReceived(const QJsonObject& response);
    void onApiError(const QString& errorMessage);
    void onApiRequestSent(const QString& endpoint);
    void showContainerDetails();
    void onServiceStatusButtonClicked(); // Yeni Service Status dialogu için slot

private:
    void createActions();
    void createMenus();
    void createToolBars();
    void createStatusBar();
    void createModernCentralWidgets(); // Modern arayüz fonksiyonu

    // Menü ve aksiyonlar
    QAction    *menuAction;
    QAction    *scanAction;
    QAction    *virusTotalAction;
    QAction    *cdrAction;
    QAction    *sandboxAction;
    QAction    *dockerAction;
    QAction    *apiKeyAction;
    QAction    *serviceStatusAction; // Yeni Service Status aksiyonu

    // Ana ekranda göstereceğimiz bileşenler
    QLabel         *statusLabel;
    QPlainTextEdit *resultTextEdit;
    QPlainTextEdit *detailedResultTextEdit;
    QPlainTextEdit *apiLogTextEdit;
    QTableWidget   *containerTableWidget;

    // Yönetici sınıflar
    ApiManager     *apiManager;
    ScanManager    *scanManager;
    ResultsView    *resultsView;
    DockerUIManager *dockerUIManager;
};

#endif // USERINTERFACE_H
