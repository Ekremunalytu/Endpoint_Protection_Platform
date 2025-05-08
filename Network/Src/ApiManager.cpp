#include "ApiManager.h"
#include <QTimer>

// Modern statik üyelerin tanımlanması
std::unique_ptr<ApiManager> ApiManager::instance = nullptr;
std::once_flag ApiManager::initInstanceFlag;

// Thread-safe singleton implementasyonu
ApiManager* ApiManager::getInstance(QObject* parent) {
    std::call_once(initInstanceFlag, [parent]() {
        instance = std::unique_ptr<ApiManager>(new ApiManager(parent));
    });
    return instance.get();
}

// Shared_ptr alternatifi
std::shared_ptr<ApiManager> ApiManager::getInstanceShared(QObject* parent) {
    static std::shared_ptr<ApiManager> sharedInstance = nullptr;
    
    if (!sharedInstance) {
        ApiManager* rawInstance = getInstance(parent);
        // Raw pointer'ı shared_ptr'ye dönüştürüyoruz, ancak instance'ın sahipliğini almıyoruz
        sharedInstance = std::shared_ptr<ApiManager>(rawInstance, [](ApiManager*) {
            // Boş deleter - gerçek nesne unique_ptr tarafından yönetiliyor
        });
    }
    
    return sharedInstance;
}

// Constructor - smart pointer kullanarak
ApiManager::ApiManager(QObject* parent)
    : QObject(parent), 
      networkManager(std::make_unique<QNetworkAccessManager>()),
      configManager(ConfigManager::getInstance()) {
    // VirusTotal API için base URL 
    baseUrl = "https://www.virustotal.com/api/v3/";
}

// Destructor implementasyonu
ApiManager::~ApiManager() {
    // networkManager smart pointer ile otomatik olarak temizlenecek
}

// Mevcut metodlar aynı kalabilir
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
            // QNetworkReply için QtObject'in deleteLater kullanımı
            QObject::connect(reply, &QObject::destroyed, []() {
                // Reply temizlendi
            });
            
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
            
            // Cevabı temizle
            reply->deleteLater();
        });
    } else {
        // POST isteği
        QJsonDocument jsonDoc(data);
        QByteArray jsonData = jsonDoc.toJson();
        
        QNetworkReply* reply = networkManager->post(request, jsonData);
        connect(reply, &QNetworkReply::finished, [this, reply]() {
            // QNetworkReply için QtObject'in deleteLater kullanımı
            QObject::connect(reply, &QObject::destroyed, []() {
                // Reply temizlendi
            });
            
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
            
            // Cevabı temizle
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

    // Multipart form data hazırla - QNetworkReply'a sahiplik verilecek
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
    connect(reply, &QNetworkReply::finished, [this, reply, fileName]() {
        // QNetworkReply için QtObject'in deleteLater kullanımı
        QObject::connect(reply, &QObject::destroyed, []() {
            // Reply temizlendi
        });
        
        if (reply->error() == QNetworkReply::NoError) {
            QByteArray responseData = reply->readAll();
            QJsonDocument jsonDoc = QJsonDocument::fromJson(responseData);

            if (!jsonDoc.isNull() && jsonDoc.isObject()) {
                QJsonObject response = jsonDoc.object();
                
                // File upload response contains the analysis ID, we need to get analysis results
                if (response.contains("data") && response["data"].isObject()) {
                    QJsonObject data = response["data"].toObject();
                    if (data.contains("id") && data.contains("type") && data["type"].toString() == "analysis") {
                        QString analysisId = data["id"].toString();
                        
                        // Şimdi analiz sonuçlarını almak için ID ile API çağrısı yap
                        // Dosya yüklendikten sonra VirusTotal'in analiz işlemi biraz zaman alabilir
                        emit responseReceived(response);  // Önce upload başarılı yanıtını gönder
                        
                        // Analiz sonuçları için 5 saniye bekle - VirusTotal'in işleme zamanı için
                        QTimer::singleShot(5000, [this, analysisId]() {
                            this->getAnalysisResults(analysisId);
                        });
                    } else {
                        emit responseReceived(response);
                    }
                } else {
                    emit responseReceived(response);
                }
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
        
        // Cevabı temizle
        reply->deleteLater();
    });
}

// Yeni metod: VirusTotal'den belirli bir analiz ID'si için sonuçları al
void ApiManager::getAnalysisResults(const QString& analysisId) {
    // VirusTotal API sonuç endpoint'i
    QString endpoint = QString("analyses/%1").arg(analysisId);
    
    // Standart API isteği yap
    makeApiRequest(endpoint);
}
