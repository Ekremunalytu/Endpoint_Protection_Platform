#include "../Headers/ApiManager.h"

ApiManager* ApiManager::getInstance(QObject* parent) {
    static ApiManager instance(parent);
    return &instance;
}

ApiManager::ApiManager(QObject* parent)
    : QObject(parent), networkManager(new QNetworkAccessManager(this)), configManager(ConfigManager::getInstance()) {
    baseUrl = "https://www.virustotal.com/api/v3";
}

void ApiManager::setApiKey(const QString& key) {
    configManager->setApiKey(key);
}

QString ApiManager::getApiKey() {
    return configManager->getApiKey();
}

bool ApiManager::hasApiKey() {
    return !getApiKey().isEmpty();
}

void ApiManager::makeApiRequest(const QString& endpoint, const QJsonObject& data) {
    QString apiKey = getApiKey();
    if (apiKey.isEmpty()) {
        emit error("API anahtarı eksik. Lütfen ayarlayın.");
        return;
    }
    QUrl url(baseUrl + endpoint);
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("x-apikey", apiKey.toUtf8());
    qDebug() << "[ApiManager] x-apikey header:" << apiKey;
    qDebug() << "[ApiManager] URL:" << url.toString();

    QNetworkReply* reply = nullptr;
    if (data.isEmpty()) {
        reply = networkManager->get(request);
    } else {
        QJsonDocument doc(data);
        QByteArray payload = doc.toJson();
        reply = networkManager->post(request, payload);
    }

    connect(reply, &QNetworkReply::finished, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QByteArray responseData = reply->readAll();
            QJsonDocument jsonResponse = QJsonDocument::fromJson(responseData);
            emit responseReceived(jsonResponse.object());
        } else {
            qDebug() << "[ApiManager] Network error:" << reply->errorString();
            qDebug() << "[ApiManager] Response data:" << reply->readAll();
            emit error(reply->errorString());
        }
        reply->deleteLater();
    });
}
