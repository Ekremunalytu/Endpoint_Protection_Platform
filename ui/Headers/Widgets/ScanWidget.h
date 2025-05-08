#ifndef SCANWIDGET_H
#define SCANWIDGET_H

#include <QWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QTextEdit>
#include <memory>

// Forward declarations
class ScanManager;
class IApiManager;
class IYaraRuleManager;
class ICdrManager;
class ISandboxManager;

/**
 * @brief Tarama işlemleri için UI bileşenlerini içeren widget
 * Offline tarama, VirusTotal taraması, CDR ve Sandbox işlemlerini yönetir
 */
class ScanWidget : public QWidget {
    Q_OBJECT

public:
    /**
     * @brief Yapıcı metod
     * @param scanManager Tarama yöneticisi 
     * @param parent Üst widget
     */
    explicit ScanWidget(ScanManager* scanManager, QWidget* parent = nullptr);

    /**
     * @brief Destructor
     */
    ~ScanWidget() override = default;

signals:
    /**
     * @brief Tarama başlatıldığında sinyal
     * @param resultVisible Sonuç alanını görünür yapma
     */
    void scanStarted(bool resultVisible = true);

private slots:
    void onOfflineScanClicked();
    void onVirusTotalScanClicked();
    void onCdrScanClicked();
    void onSandboxScanClicked();

    // Yeni eklenen slotlar
    void updateProgress(int progress);
    void displayResults(const QString& scanType, const QString& filePath, const QString& result, bool isClean);
    void displayError(const QString& error);

private:
    void createLayout();
    void setupConnections();
    
    ScanManager* m_scanManager;
    
    // UI bileşenleri
    QPushButton* m_offlineScanBtn;
    QPushButton* m_virusTotalScanBtn;
    QPushButton* m_cdrScanBtn;
    QPushButton* m_sandboxScanBtn;

    // Yeni eklenen bileşenler
    QProgressBar* m_progressBar;
    QTextEdit* m_resultsTextEdit;
};

#endif // SCANWIDGET_H