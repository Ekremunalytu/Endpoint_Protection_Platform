#ifndef SERVICESTATUSDIALOG_H
#define SERVICESTATUSDIALOG_H

#include <QDialog>
#include <QTabWidget>
#include <QTableWidget>
#include <QLabel>
#include <QPushButton>

// Forward declarations
class IApiManager;
class ScanManager;
class DockerUIManager;

/**
 * @brief Servis durumlarını gösteren diyalog
 * API, Docker, CDR ve Sandbox servislerinin durumunu gösterir
 */
class ServiceStatusDialog : public QDialog {
    Q_OBJECT
private:
    IApiManager* m_apiManager;
    ScanManager* m_scanManager;
    DockerUIManager* m_dockerUIManager;
    QTabWidget* m_tabWidget;
    QTableWidget* m_statusTable;
    QTableWidget* m_containerTable;
    QLabel* m_runningContainerValue;
    QLabel* m_totalContainerValue;
    QLabel* m_imageValue;
    QPushButton* m_refreshButton;

public:
    /**
     * @brief Yapıcı metod
     * @param apiManager VirusTotal API manager
     * @param scanManager Tarama yöneticisi
     * @param dockerUIManager Docker UI yöneticisi
     * @param parent Üst widget
     */
    ServiceStatusDialog(IApiManager* apiManager, ScanManager* scanManager, DockerUIManager* dockerUIManager, QWidget* parent = nullptr);

private:
    void createUI();
    void updateServiceStatus();
    void updateContainerList();
    void setupConnections();
};

#endif // SERVICESTATUSDIALOG_H