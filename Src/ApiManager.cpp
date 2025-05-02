#include "../Headers/ApiManager.h"

ApiManager* ApiManager::getInstance(QObject* parent) {
    static ApiManager instance(parent);
    return &instance;
}

ApiManager::ApiManager(QObject* parent)
    : QObject(parent), networkManager(new QNetworkAccessManager(this)), configManager(ConfigManager::getInstance()) {
    // API URL'ini doğru formatta ayarla - sonunda / olmadan
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
    
    // URL formatını düzelt - endpoint'in başında / olduğundan emin ol
    QString formattedEndpoint = endpoint;
    if (!endpoint.startsWith('/')) {
        formattedEndpoint = "/" + endpoint;
    }
    
    // Debug için tam URL'i göster
    QUrl url(baseUrl + formattedEndpoint);
    qDebug() << "API URL:" << url.toString();
    
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("x-apikey", apiKey.toUtf8());
    qDebug() << "[ApiManager] x-apikey header:" << apiKey;

    // Sinyal tetikle - isteğin gönderildiğini bildir
    emit requestSent(endpoint);

    QNetworkReply* reply = nullptr;
    
    // Veri içeren bir istek için POST, olmayan için GET kullan
    if (data.isEmpty()) {
        qDebug() << "[ApiManager] Sending GET request to:" << url.toString();
        reply = networkManager->get(request);
    } else {
        QJsonDocument doc(data);
        QByteArray payload = doc.toJson();
        qDebug() << "[ApiManager] Sending POST request to:" << url.toString();
        qDebug() << "[ApiManager] Payload:" << QString(payload);
        reply = networkManager->post(request, payload);
    }

    connect(reply, &QNetworkReply::finished, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QByteArray responseData = reply->readAll();
            qDebug() << "[ApiManager] Successful response:" << QString(responseData);
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

void ApiManager::uploadFileToVirusTotal(const QString& filePath, const QString& fileName, const QByteArray& fileData) {
    QString apiKey = getApiKey();
    if (apiKey.isEmpty()) {
        emit error("API anahtarı eksik. Lütfen ayarlayın.");
        return;
    }

    QUrl url(baseUrl + "/files");
    QNetworkRequest request(url);
    request.setRawHeader("x-apikey", apiKey.toUtf8());

    // Create multipart message
    QHttpMultiPart *multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    
    // Add the file data to the multipart message
    QHttpPart filePart;
    filePart.setHeader(QNetworkRequest::ContentDispositionHeader, 
                       QVariant("form-data; name=\"file\"; filename=\"" + fileName + "\""));
    filePart.setBody(fileData);
    multiPart->append(filePart);

    // Send the request
    qDebug() << "[ApiManager] Uploading file to VirusTotal:" << fileName;
    QNetworkReply* reply = networkManager->post(request, multiPart);
    multiPart->setParent(reply); // The multiPart object will be deleted when the reply is deleted

    // Handle the response
    connect(reply, &QNetworkReply::finished, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QByteArray responseData = reply->readAll();
            qDebug() << "[ApiManager] File upload successful. Response:" << QString(responseData);
            QJsonDocument jsonResponse = QJsonDocument::fromJson(responseData);
            emit responseReceived(jsonResponse.object());
        } else {
            qDebug() << "[ApiManager] File upload failed:" << reply->errorString();
            qDebug() << "[ApiManager] Response data:" << reply->readAll();
            emit error("File upload failed: " + reply->errorString());
        }
        reply->deleteLater();
    });
}
