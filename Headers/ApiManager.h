#ifndef APIMANAGER_H
#define APIMANAGER_H

#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include <QHttpMultiPart>
#include <mutex>
#include "ConfigManager.h"
#include "Interfaces/IApiManager.h"

class ApiManager : public QObject, public IApiManager {
    Q_OBJECT

private:
    QNetworkAccessManager* networkManager;
    ConfigManager* configManager;
    QString baseUrl;

    // Singleton için statik değişkenler 
    static ApiManager* instance;
    static std::mutex mutex;

    explicit ApiManager(QObject* parent = nullptr);

public:
    // Singleton pattern güvenli implementasyonu
    static ApiManager* getInstance(QObject* parent = nullptr);

    // IApiManager arayüzünü uygulama
    void setApiKey(const QString& key) override;
    QString getApiKey() override;
    bool hasApiKey() override;
    void makeApiRequest(const QString& endpoint, const QJsonObject& data = QJsonObject()) override;
    void uploadFileToVirusTotal(const QString& filePath, const QString& fileName, const QByteArray& fileData) override;

signals:
    void responseReceived(const QJsonObject& response);
    void error(const QString& errorMessage);
    void requestSent(const QString& endpoint);
};

#endif // APIMANAGER_H
