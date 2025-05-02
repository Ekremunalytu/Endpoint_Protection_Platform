#ifndef DOCKERUIMANAGER_H
#define DOCKERUIMANAGER_H

#include <QObject>
#include <QTableWidget>
#include <QPlainTextEdit>

class DockerManager;

class DockerUIManager : public QObject
{
    Q_OBJECT

public:
    explicit DockerUIManager(QObject *parent = nullptr);
    ~DockerUIManager();
    
    // UI bileşenlerini ayarla
    void setTableWidget(QTableWidget* tableWidget);
    void setLogTextEdit(QPlainTextEdit* logTextEdit);
    
    // Docker konteyner yönetim işlemleri
    void showContainerDetails();
    void updateContainerList();
    bool isDockerAvailable() const;
    
private:
    QTableWidget* m_containerTableWidget;
    QPlainTextEdit* m_logTextEdit;
    DockerManager* m_dockerManager;
};

#endif // DOCKERUIMANAGER_H