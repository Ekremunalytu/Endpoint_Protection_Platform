#ifndef APIMANAGER_H
#define APIMANAGER_H

#include <QObject>
#include <QString>
#include <QNetworkReply>
#include <QUrl>

/**
 * @brief ApiManager, VirusTotal API entegrasyonunu yönetmek için kullanılacak sınıftır.
 *
 * Bu header dosyası, dosya, URL ve hash gönderimi işlemleri için temel fonksiyon prototiplerini tanımlar.
 * Fonksiyon implementasyonları ayrı bir kaynak dosyasında yapılacaktır.
 */
class ApiManager : public QObject
{
    Q_OBJECT

private:
     std::string m_apiKey;
public:
    explicit ApiManager(QObject *parent = nullptr);
    ~ApiManager();

    std::string getApiKey() const;
    /**
     * @brief Belirtilen dosyayı VirusTotal API'ye gönderir.
     * @param filePath Gönderilecek dosyanın yolu.
     * @param apiResponse API'den alınan cevabı içerir.
     * @return İşlem başarılı ise true, aksi halde false.
     */


    bool sendFileToVirusTotal();

    /**
     * @brief Belirtilen URL'i VirusTotal API'ye gönderir.
     * @param url Kontrol edilecek URL.
     * @param apiResponse API'den alınan cevabı içerir.
     * @return İşlem başarılı ise true, aksi halde false.
     */
    bool sendUrlToVirusTotal(const QString &url, QString &apiResponse);

    /**
     * @brief Belirtilen hash değerini VirusTotal API'ye gönderir.
     * @param hash Kontrol edilecek hash değeri.
     * @param apiResponse API'den alınan cevabı içerir.
     * @return İşlem başarılı ise true, aksi halde false.
     */
    bool sendHashToVirusTotal(const QString &hash, QString &apiResponse);

    /**
     * @brief VirusTotal API için GET isteği gönderir.
     * @param url İstek gönderilecek URL.
     * @return QNetworkReply nesnesi; istek tamamlandığında işlenmek üzere.
     */
    QNetworkReply* sendGetRequest(const QUrl &url);

    /**
     * @brief VirusTotal API için POST isteği gönderir.
     * @param url İstek gönderilecek URL.
     * @param data Gönderilecek POST verileri.
     * @return QNetworkReply nesnesi; istek tamamlandığında işlenmek üzere.
     */
    QNetworkReply* sendPostRequest(const QUrl &url, const QByteArray &data);
};

#endif // APIMANAGER_H
