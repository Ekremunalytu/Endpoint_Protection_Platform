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

    explicit ApiManager(QObject* parent = nullptr);

public:
    static ApiManager* getInstance(QObject* parent = nullptr);

    void setApiKey(const QString& key);
    QString getApiKey();
    bool hasApiKey();
    void makeApiRequest(const QString& endpoint, const QJsonObject& data = QJsonObject());

signals:
    void responseReceived(const QJsonObject& response);
    void error(const QString& errorMessage);
    void requestSent(const QString& endpoint); // Yeni eklenen sinyal
};

#endif // APIMANAGER_H
