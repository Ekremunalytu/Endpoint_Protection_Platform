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
#include "ApiManager.h"
#include "YaraRuleManager.h"
#include <QJsonObject>

class QAction;
class QMenu;
class QToolBar;

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
    void onApiResponseReceived(const QJsonObject& response);
    void onApiError(const QString& errorMessage);
    void onApiRequestSent(const QString& endpoint);

private:
    void createActions();
    void createMenus();
    void createToolBars();
    void createStatusBar();
    void createCentralWidgets();
    void createModernCentralWidgets(); // Modern arayüz fonksiyonu
    void setupTextEditStyle(QPlainTextEdit* textEdit);
    void showApiKeyDialog();
    void updateStatus(const QString& message);
    void appendResult(const QString& engine, const QString& result);
    void showNormalResults(const QJsonObject& response);
    void showDetailedResults(const QJsonObject& response);

    // Menü ve aksiyonlar
    QAction    *menuAction;
    QAction    *scanAction;
    QAction    *virusTotalAction;
    QAction    *apiKeyAction;

    // Ana ekranda göstereceğimiz bileşenler
    QLabel         *statusLabel;      // Altta kısa mesajlar için
    QPlainTextEdit *resultTextEdit;   // Normal görünüm için
    QPlainTextEdit *detailedResultTextEdit; // Detaylı görünüm için
    QPlainTextEdit *apiLogTextEdit;        // API iletişimi için
    ApiManager     *apiManager;       // API yöneticisi
    YaraRuleManager *yaraManager;     // YARA yöneticisi (dinamik tarama için)
};

#endif // USERINTERFACE_H
