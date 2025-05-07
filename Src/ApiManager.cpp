#include "../Headers/ApiManager.h"

// Static üyelerin tanımlanması
ApiManager* ApiManager::instance = nullptr;
std::mutex ApiManager::mutex;

ApiManager* ApiManager::getInstance(QObject* parent) {
    // Double-checked locking pattern ile thread-safe singleton
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(mutex);
        if (instance == nullptr) {
            instance = new ApiManager(parent);
        }
    }
    return instance;
}

ApiManager::ApiManager(QObject* parent)
    : QObject(parent), networkManager(new QNetworkAccessManager(this)), configManager(ConfigManager::getInstance()) {
    // VirusTotal API için base URL 
    baseUrl = "https://www.virustotal.com/api/v3/";
}

void ApiManager::setApiKey(const QString& key) {
    configManager->setApiKey(key);
}

QString ApiManager::getApiKey() {
    return configManager->getApiKey();
}

bool ApiManager::hasApiKey() {
    return configManager->hasApiKey();
}

void ApiManager::makeApiRequest(const QString& endpoint, const QJsonObject& data) {
    // Güvenlik kontrolü: API Key var mı?
    if (!hasApiKey()) {
        emit error("API Key not set. Please set an API Key first.");
        return;
    }

    QString fullUrl = baseUrl + endpoint;
    QNetworkRequest request((QUrl(fullUrl)));
    
    // Gerekli header'ları ekle
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("x-apikey", getApiKey().toUtf8());
    
    // Request endpoint'ini log için emit et
    emit requestSent(endpoint);
    
    // İstek tipi kontrolü ve gönderim
    if (data.isEmpty()) {
        // GET isteği
        QNetworkReply* reply = networkManager->get(request);
        connect(reply, &QNetworkReply::finished, [this, reply]() {
            // Yanıt işleme
            if (reply->error() == QNetworkReply::NoError) {
                QByteArray responseData = reply->readAll();
                QJsonDocument jsonDoc = QJsonDocument::fromJson(responseData);
                
                if (!jsonDoc.isNull() && jsonDoc.isObject()) {
                    emit responseReceived(jsonDoc.object());
                } else {
                    emit error("Invalid response format");
                }
            } else {
                emit error(QString("Network error: %1").arg(reply->errorString()));
            }
            
            reply->deleteLater();
        });
    } else {
        // POST isteği
        QJsonDocument jsonDoc(data);
        QByteArray jsonData = jsonDoc.toJson();
        
        QNetworkReply* reply = networkManager->post(request, jsonData);
        connect(reply, &QNetworkReply::finished, [this, reply]() {
            // Yanıt işleme
            if (reply->error() == QNetworkReply::NoError) {
                QByteArray responseData = reply->readAll();
                QJsonDocument jsonDoc = QJsonDocument::fromJson(responseData);
                
                if (!jsonDoc.isNull() && jsonDoc.isObject()) {
                    emit responseReceived(jsonDoc.object());
                } else {
                    emit error("Invalid response format");
                }
            } else {
                emit error(QString("Network error: %1").arg(reply->errorString()));
            }
            
            reply->deleteLater();
        });
    }
}

void ApiManager::uploadFileToVirusTotal(const QString& filePath, const QString& fileName, const QByteArray& fileData) {
    // API Key kontrolü
    if (!hasApiKey()) {
        emit error("API Key not set. Please set an API Key first.");
        return;
    }

    // Dosya verisi kontrolü
    if (fileData.isEmpty()) {
        emit error("File is empty");
        return;
    }

    // İstek için gerekli yapılar
    QString endpoint = "files";
    QString fullUrl = baseUrl + endpoint;
    QNetworkRequest request((QUrl(fullUrl)));

    // Header'ları ayarla
    request.setRawHeader("x-apikey", getApiKey().toUtf8());

    // Multipart form data hazırla
    QHttpMultiPart *multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);

    // Dosya için part hazırla
    QHttpPart filePart;
    filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant(QString("form-data; name=\"file\"; filename=\"%1\"").arg(fileName)));
    filePart.setHeader(QNetworkRequest::ContentTypeHeader, QVariant("application/octet-stream"));
    filePart.setBody(fileData);

    multiPart->append(filePart);

    // Log için endpoint'i emit et
    emit requestSent("files (upload)");

    // POST isteği gönder
    QNetworkReply* reply = networkManager->post(request, multiPart);
    multiPart->setParent(reply); // multiPart'ın sahipliğini reply'a ver

    // Yanıtı dinle
    connect(reply, &QNetworkReply::finished, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QByteArray responseData = reply->readAll();
            QJsonDocument jsonDoc = QJsonDocument::fromJson(responseData);

            if (!jsonDoc.isNull() && jsonDoc.isObject()) {
                emit responseReceived(jsonDoc.object());
            } else {
                emit error("Invalid response format");
            }
        } else {
            // Özel hata durumları için analiz
            QByteArray errorData = reply->readAll();
            QJsonDocument errorDoc = QJsonDocument::fromJson(errorData);
            
            if (!errorDoc.isNull() && errorDoc.isObject()) {
                QJsonObject errorObj = errorDoc.object();
                if (errorObj.contains("error")) {
                    QJsonObject error = errorObj["error"].toObject();
                    QString code = error["code"].toString();
                    QString message = error["message"].toString();
                    
                    emit this->error(QString("API Error (%1): %2 - server replied: %3")
                                   .arg(reply->errorString())
                                   .arg(code)
                                   .arg(message));
                } else {
                    emit error(QString("Network error: %1").arg(reply->errorString()));
                }
            } else {
                emit error(QString("Network error: %1").arg(reply->errorString()));
            }
        }

        reply->deleteLater();
    });
}
