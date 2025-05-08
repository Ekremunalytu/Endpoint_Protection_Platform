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
#include <memory>
#include "ConfigManager.h"
#include "Interfaces/IApiManager.h"

class ApiManager : public QObject, public IApiManager {
    Q_OBJECT

private:
    std::unique_ptr<QNetworkAccessManager> networkManager;
    std::shared_ptr<ConfigManager> configManager;
    QString baseUrl;

    // Modern singleton için statik değişkenler 
    static std::unique_ptr<ApiManager> instance;
    static std::once_flag initInstanceFlag;

    explicit ApiManager(QObject* parent = nullptr);
    
    // Delete copy constructor and assignment operator
    ApiManager(const ApiManager&) = delete;
    ApiManager& operator=(const ApiManager&) = delete;

public:
    // Destructor
    virtual ~ApiManager();
    
    // Modern singleton pattern güvenli implementasyonu
    static ApiManager* getInstance(QObject* parent = nullptr);
    
    // Shared_ptr alternatifi
    static std::shared_ptr<ApiManager> getInstanceShared(QObject* parent = nullptr);

    // IApiManager arayüzünü uygulama
    void setApiKey(const QString& key) override;
    QString getApiKey() override;
    bool hasApiKey() override;
    void makeApiRequest(const QString& endpoint, const QJsonObject& data = QJsonObject()) override;
    void uploadFileToVirusTotal(const QString& filePath, const QString& fileName, const QByteArray& fileData) override;
    
    // Additional methods for API handling
    void getAnalysisResults(const QString& analysisId);

signals:
    void responseReceived(const QJsonObject& response);
    void error(const QString& errorMessage);
    void requestSent(const QString& endpoint);
};

#endif // APIMANAGER_H
