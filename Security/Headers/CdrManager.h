#ifndef CDRMANAGER_H
#define CDRMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include "Interfaces/Headers/ICdrManager.h" // Changed from Interfaces/IDockerManager.h
#include "Docker/Headers/DockerManager.h" // Changed from Docker/Headers/DockerManager.h

class CdrManager : public QObject, public ICdrManager {
    Q_OBJECT

public:
    CdrManager(QObject *parent = nullptr);
    ~CdrManager();

    // ICdrManager arayüzünü uygulama
    bool initialize() override;
    void setCdrImageName(const QString& imageName) override;
    QString getCurrentImageName() const override;
    QStringList getAvailableCdrImages() const override;
    bool processFile(const QString& filePath) override;
    QString getCleanedFilePath(const QString& originalFilePath) override;

private:
    DockerManager *dockerManager;
    QString cdrImageName;
    QString outputDir; // Temizlenmiş dosyaların çıkış dizini
    
    // Yardımcı metotlar
    QString generateOutputFilename(const QString& inputFilePath);
    QJsonObject parseResults(const QString& resultData);
};

#endif // CDRMANAGER_H