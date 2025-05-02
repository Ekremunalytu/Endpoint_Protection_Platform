#ifndef CDRMANAGER_H
#define CDRMANAGER_H

#include <QString>
#include <QJsonObject>
#include "DockerManager.h"

class CdrManager : public QObject {
    Q_OBJECT

public:
    CdrManager(QObject *parent = nullptr);
    ~CdrManager();

    bool initialize();
    bool processFile(const QString& filePath);
    QString getCleanedFilePath(const QString& originalFilePath);
    QString generateOutputFilename(const QString& inputFilePath);

private:
    DockerManager *dockerManager;
    QString cdrImageName;
    QString outputDir;
    
    QJsonObject parseResults(const QString& resultData);
};

#endif // CDRMANAGER_H