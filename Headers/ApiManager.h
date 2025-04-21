#ifndef APIMANAGER_H
#define APIMANAGER_H

#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QJsonObject>
#include "ConfigManager.h"
#include <QDebug>

class ApiManager : public QObject {
    Q_OBJECT

private:
    QNetworkAccessManager* networkManager;
    ConfigManager* configManager;
    QString baseUrl;

    ApiManager(QObject* parent = nullptr) : QObject(parent) {
        networkManager = new QNetworkAccessManager(this);
        configManager = ConfigManager::getInstance();
        baseUrl = "https://www.virustotal.com/api/v3"; // VirusTotal API v3 endpoint
    }

public:
    static ApiManager* getInstance(QObject* parent = nullptr) {
        static ApiManager* instance = new ApiManager(parent);
        return instance;
    }

    void setApiKey(const QString& key) {
        configManager->setApiKey(key);
    }

    QString getApiKey() {
        return configManager->getApiKey();
    }

    bool hasApiKey() {
        return configManager->hasApiKey();
    }

    void makeApiRequest(const QString& endpoint, const QJsonObject& data = QJsonObject()) {
        if (!hasApiKey()) {
            emit error("API key not set");
            return;
        }

        QNetworkRequest request;
        request.setUrl(QUrl(baseUrl + endpoint));
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        request.setRawHeader("x-apikey", configManager->getApiKey().toUtf8());

        QNetworkReply* reply;
        if (data.isEmpty()) {
            reply = networkManager->get(request);
        } else {
            reply = networkManager->post(request, QJsonDocument(data).toJson());
        }

        connect(reply, &QNetworkReply::finished, [this, reply]() {
            if (reply->error() == QNetworkReply::NoError) {
                QJsonDocument response = QJsonDocument::fromJson(reply->readAll());
                emit responseReceived(response.object());
            } else {
                emit error(QString("Network Error: %1").arg(reply->errorString()));
                qDebug() << "Error Response:" << reply->readAll();
            }
            reply->deleteLater();
        });
    }

signals:
    void responseReceived(const QJsonObject& response);
    void error(const QString& errorMessage);
};

#endif // APIMANAGER_H
