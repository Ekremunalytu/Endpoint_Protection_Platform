#ifndef ICDRMANAGER_H
#define ICDRMANAGER_H

#include <QString>
#include <QStringList>
#include <QJsonObject>

// Content Disarm & Reconstruction servisini kullanmak için soyut arayüz
class ICdrManager {
public:
    virtual ~ICdrManager() = default;
    
    virtual bool initialize() = 0;
    virtual void setCdrImageName(const QString& imageName) = 0;
    virtual QString getCurrentImageName() const = 0;
    virtual QStringList getAvailableCdrImages() const = 0;
    virtual bool processFile(const QString& filePath) = 0;
    virtual QString getCleanedFilePath(const QString& originalFilePath) = 0;
};

#endif // ICDRMANAGER_H