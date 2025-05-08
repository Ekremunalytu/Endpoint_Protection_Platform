#ifndef IAPIMANAGER_H
#define IAPIMANAGER_H

#include <QString>
#include <QJsonObject>
#include <QByteArray>
#include <QObject>

// API servisini kullanmak için soyut arayüz
class IApiManager {
public:
    virtual ~IApiManager() = default;
    
    virtual void setApiKey(const QString& key) = 0;
    virtual QString getApiKey() = 0;
    virtual bool hasApiKey() = 0;
    virtual void makeApiRequest(const QString& endpoint, const QJsonObject& data = QJsonObject()) = 0;
    virtual void uploadFileToVirusTotal(const QString& filePath, const QString& fileName, const QByteArray& fileData) = 0;
};

#endif // IAPIMANAGER_H