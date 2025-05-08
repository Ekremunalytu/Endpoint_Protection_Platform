#ifndef USERINTERFACE_H
#define USERINTERFACE_H

#include <QMainWindow>
#include <QString>
#include <QAction>
#include <QPlainTextEdit>
#include <QStatusBar>
#include <QTableWidget>
#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QTabWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QProgressDialog>

#include "ApiManager.h"
#include "DbManager.h"
#include "YaraRuleManager.h"
#include "ScanManager.h"
#include "ResultsView.h"
#include "DockerUIManager.h"

// Forward declarations for interfaces
class IApiManager;
class IDbManager;
class IYaraRuleManager;
class ICdrManager;
class ISandboxManager;
class IDockerManager;

class ApiKeyDialog : public QDialog {
    Q_OBJECT
private:
    QLineEdit* apiKeyLineEdit;
public:
    explicit ApiKeyDialog(QWidget *parent = nullptr);
    QString getApiKey() const { return apiKeyLineEdit->text(); }
};

class DockerImageSelectionDialog : public QDialog {
    Q_OBJECT
private:
    QComboBox* imageComboBox;
public:
    DockerImageSelectionDialog(const QStringList& availableImages, const QString& currentImage, const QString& serviceType, QWidget* parent = nullptr);
    QString getSelectedImage() const;
};

class ServiceStatusDialog : public QDialog {
    Q_OBJECT
private:
    IApiManager* apiManager;
    ScanManager* scanManager;
    DockerUIManager* dockerUIManager;
    QTabWidget* tabWidget;
    QTableWidget* statusTable;
    QTableWidget* containerTable;
    QLabel* runningContainerValue;
    QLabel* totalContainerValue;
    QLabel* imageValue;
    QPushButton* refreshButton;

public:
    ServiceStatusDialog(IApiManager* apiManager, ScanManager* scanManager, DockerUIManager* dockerUIManager, QWidget* parent = nullptr);

private:
    void createUI();
    void updateServiceStatus();
    void updateContainerList();
    void setupConnections();
};

class HistoryDialog : public QDialog {
    Q_OBJECT
private:
    QTabWidget* tabWidget;
    QTableWidget* scanHistoryTable;
    QTableWidget* vtHistoryTable;
    QTableWidget* cdrHistoryTable;
    QTableWidget* sandboxHistoryTable;
    QPushButton* clearHistoryButton;
    QPushButton* exportHistoryButton;
    QPushButton* closeButton;

public:
    explicit HistoryDialog(QWidget* parent = nullptr);

private:
    void createUI();
    void loadHistory();
    void setupConnections();
};

class MainWindow : public QMainWindow {
    Q_OBJECT
private:
    // Actions
    QAction* menuAction;
    QAction* scanAction;
    QAction* virusTotalAction;
    QAction* cdrAction;            // CDR işlemi için aksiyon
    QAction* sandboxAction;        // Sandbox analizi için aksiyon
    QAction* apiKeyAction;
    QAction* dockerAction;
    QAction* serviceStatusAction;
    QLabel* statusLabel;
    QPlainTextEdit* resultTextEdit;
    QPlainTextEdit* detailedResultTextEdit;
    QPlainTextEdit* apiLogTextEdit;
    
    // Manager sınıfları - artık hepsi arayüzler üzerinden kullanılacak
    IApiManager* apiManager;
    IYaraRuleManager* yaraRuleManager;
    ICdrManager* cdrManager;
    ISandboxManager* sandboxManager;
    IDbManager* dbManager;
    IDockerManager* dockerManager; // DockerManager yerine IDockerManager kullanılıyor
    
    ScanManager* scanManager;
    ResultsView* resultsView;
    DockerUIManager* dockerUIManager;

    // İlerleme göstergesi
    QProgressDialog* progressDialog;
    int currentProgress;

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    void createActions();
    void createMenus();
    void createToolBars();
    void createStatusBar();
    void createModernCentralWidgets();
    void setupProgressDialog();
    void initializeServices();

    // İşlem işleyicileri
    void handleOperationStarted(const QString& operationType);
    void handleOperationCompleted(const QString& operationType, bool success);
    void handleProgressUpdated(int percentage);

private slots:
    void onApiResponseReceived(const QJsonObject& response);
    void onApiError(const QString& errorMessage);
    void onApiRequestSent(const QString& endpoint);
    void onScanButtonClicked();
    void onApiKeyButtonClicked();
    void onsendVirusTotalButtonClicked();
    void onCdrButtonClicked();
    void onSandboxButtonClicked();
    void onServiceStatusButtonClicked();
    void showContainerDetails();
    void onHistoryButtonClicked();
};

#endif // USERINTERFACE_H
