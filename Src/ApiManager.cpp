#include "../Headers/ApiManager.h"
#include <curl/curl.h>
#include <iostream>
#include <sstream>

// Yazma callback fonksiyonu: cURL tarafından dönen veriyi bir std::string'e yazar.
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t totalSize = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

ApiManager::ApiManager(QObject *parent)
    : QObject(parent),
      m_apiKey("secret-key")  // API key burada atanıyor.
{
}

ApiManager::~ApiManager()
{
}

std::string ApiManager::getApiKey() const {
    return m_apiKey;
}

// Dosya gönderimi için fonksiyon
bool ApiManager::sendFileToVirusTotal() {
    CURL *hnd = curl_easy_init();
    if (!hnd) {
        std::cerr << "Curl initialization failed" << std::endl;
        return false;
    }

    std::string responseString; // Response verisini burada tutacağız.

    // Callback ayarlanıyor.
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &responseString);

    // POST isteğini ayarla.
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/files");

    // HTTP header'ları ayarla.
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "accept: application/json");

    // Dinamik API key kullanımı.
    std::string apiHeader = "x-apikey: " + this->getApiKey();
    std::cout << "Using header: " << apiHeader << std::endl;
    headers = curl_slist_append(headers, apiHeader.c_str());

    // multipart/form-data header (eğer boundary gerekli ise)
    headers = curl_slist_append(headers, "content-type: multipart/form-data; boundary=---011000010111000001101001");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    // POST verisini ayarla.
    const char* postFields =
        "-----011000010111000001101001\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "data:text/plain;name=test.txt;base64,aGFsbG8=\r\n"
        "-----011000010111000001101001--";
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, postFields);

    // İsteği gerçekleştir.
    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(ret) << std::endl;
    } else {
        std::cout << "Response: " << responseString << std::endl;
    }

    // Temizlik yap.
    curl_easy_cleanup(hnd);
    curl_slist_free_all(headers);

    return (ret == CURLE_OK);
}

// Hash sorgulaması için fonksiyon. Gelen JSON response'u apiResponse parametresine yazıyoruz.
bool ApiManager::sendHashToVirusTotal(const QString &hash, QString &apiResponse) {
    CURL *hnd = curl_easy_init();
    if (!hnd) {
        std::cerr << "Curl initialization failed" << std::endl;
        return false;
    }

    std::string responseString;

    // Callback ayarlanıyor.
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &responseString);

    // GET isteğini ayarla.
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");

    // Hash değerini URL içerisine dinamik olarak ekleyebilirsiniz.
    // Örneğin: "https://www.virustotal.com/api/v3/files/" + hash.toStdString();
    std::string url = "https://www.virustotal.com/api/v3/files/" + hash.toStdString();
    curl_easy_setopt(hnd, CURLOPT_URL, url.c_str());

    // HTTP header'ları ayarla.
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "accept: application/json");

    // Dinamik API key kullanımı
    std::string apiHeader = "x-apikey: " + this->getApiKey();
    headers = curl_slist_append(headers, apiHeader.c_str());
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    // İsteği gerçekleştir.
    CURLcode ret = curl_easy_perform(hnd);
    if(ret != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(ret) << std::endl;
    } else {
        // responseString JSON formatında dönecektir, bunu apiResponse'ya aktarıyoruz.
        apiResponse = QString::fromStdString(responseString);
        std::cout << "Response: " << responseString << std::endl;
    }

    // Temizlik yap.
    curl_easy_cleanup(hnd);
    curl_slist_free_all(headers);

    return (ret == CURLE_OK);
}
