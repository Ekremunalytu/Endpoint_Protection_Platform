#ifndef DOCKERUIMANAGER_H
#define DOCKERUIMANAGER_H

#include <QObject>
#include <QString>
#include <QtCore/QJsonArray>
#include <QVariant>
#include <QTableWidget>
#include <QPlainTextEdit>

// Arayüz için forward declaration
class IDockerManager;

class DockerUIManager : public QObject
{
    Q_OBJECT

public:
    explicit DockerUIManager(QObject *parent = nullptr);
    ~DockerUIManager();
    
    // UI bileşenlerini ayarla
    void setTableWidget(QTableWidget* tableWidget);
    void setLogTextEdit(QPlainTextEdit* logTextEdit);
    
    // Docker manager'ı ayarla
    void setDockerManager(IDockerManager* dockerManager);
    
    // Docker konteyner yönetim işlemleri
    void showContainerDetails();
    void updateContainerList();
    bool isDockerAvailable() const;
    
    // Container ve imaj bilgilerini getir
    QJsonArray getDockerContainers();
    QJsonArray getDockerImages();
    
private:
    QTableWidget* m_containerTableWidget;
    QPlainTextEdit* m_logTextEdit;
    IDockerManager* m_dockerManager;
};

#endif // DOCKERUIMANAGER_H