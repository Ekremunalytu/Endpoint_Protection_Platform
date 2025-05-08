#include "ApplicationStartup.h"
#include "ServiceLocator.h"

// Tüm servis sınıflarının başlık dosyalarını dahil et
#include "Network/Headers/ApiManager.h"
#include "Security/Headers/YaraRuleManager.h"
#include "Security/Headers/CdrManager.h"
#include "Security/Headers/SandboxManager.h"
#include "Database/Headers/DbManager.h"
#include "Docker/Headers/DockerManager.h"
#include "ConfigManager.h"
#include "Scanning/Headers/ScanManager.h" // Add this line

#include <QDebug>
#include <QFile>
#include <QApplication>
#include <QTextStream>

ApplicationStartup::ApplicationStartup(QObject *parent) : QObject(parent)
{
    // QApplication pointer'ını al
    app = qobject_cast<QApplication*>(parent);
    if (!app) {
        qWarning() << "ApplicationStartup: QApplication referansı alınamadı!";
    }
}

ApplicationStartup::~ApplicationStartup()
{
    cleanup();
}

void ApplicationStartup::initialize()
{
    qDebug() << "ApplicationStartup: Başlatılıyor...";
    
    // Servisleri başlat
    initializeServices();
    
    // Servisleri kaydet
    registerServices();
    
    // Stil dosyalarını yükle
    loadStyleSheets();
    
    qDebug() << "ApplicationStartup: Tüm servisler ve stiller hazır.";
}

void ApplicationStartup::initializeServices()
{
    qDebug() << "ApplicationStartup: Servisler başlatılıyor...";
    
    // Not: Bu aşamada herhangi bir dinamik oluşturma veya özel yapılandırma yapılabilir
    // Şu an için sadece mevcut servisleri kullanıyoruz
}

void ApplicationStartup::registerServices()
{
    qDebug() << "ApplicationStartup: Servisler kaydediliyor...";
    
    // Tüm singleton ve servis nesneleri al
    ApiManager* apiManager = ApiManager::getInstance();
    YaraRuleManager* yaraRuleManager = new YaraRuleManager(); // Assuming this is how it's created
    DbManager* dbManager = DbManager::getInstance();
    DockerManager* dockerManager = new DockerManager(this); // Assuming this is correct
    CdrManager* cdrManager = new CdrManager(this); // Assuming this is correct
    SandboxManager* sandboxManager = new SandboxManager(this); // Assuming this is correct

    // ScanManager'ı oluşturmadan önce bağımlılıklarını ServiceLocator'dan al
    IApiManager* iApiManager = ServiceLocator::getApiManager();
    IYaraRuleManager* iYaraRuleManager = ServiceLocator::getYaraRuleManager();
    ICdrManager* iCdrManager = ServiceLocator::getCdrManager();
    ISandboxManager* iSandboxManager = ServiceLocator::getSandboxManager();
    IDbManager* iDbManager = ServiceLocator::getDbManager();

    ScanManager* scanManager = new ScanManager(
        iApiManager,
        iYaraRuleManager,
        iCdrManager,
        iSandboxManager,
        iDbManager,
        this
    );
    
    // Tüm servisleri ServiceLocator'a kaydet
    ServiceLocator::provide(apiManager); // Bu zaten IApiManager olarak kaydedilmiş olabilir, kontrol edin
    ServiceLocator::provide(yaraRuleManager); // Bu zaten IYaraRuleManager olarak kaydedilmiş olabilir
    ServiceLocator::provide(dbManager); // Bu zaten IDbManager olarak kaydedilmiş olabilir
    ServiceLocator::provide(dockerManager);
    ServiceLocator::provide(cdrManager); // Bu zaten ICdrManager olarak kaydedilmiş olabilir
    ServiceLocator::provide(sandboxManager); // Bu zaten ISandboxManager olarak kaydedilmiş olabilir
    ServiceLocator::provide(scanManager);
    
    // Başlatma ve durum kontrolleri
    try {
        // YARA başlatma ve hata kontrolü
        std::error_code yaraError = yaraRuleManager->initialize();
        if (yaraError) {
            qWarning() << "ApplicationStartup: YARA başlatma hatası:" << QString::fromStdString(yaraError.message());
        } else {
            qDebug() << "ApplicationStartup: YARA başlatıldı.";
            
            // Kural dizini yükleme
            std::error_code rulesError = yaraRuleManager->loadRules("Rules/test.yar");
            if (rulesError) {
                qWarning() << "ApplicationStartup: YARA kuralları yükleme hatası:" << QString::fromStdString(rulesError.message());
            } else {
                qDebug() << "ApplicationStartup: YARA kuralları yüklendi.";
            }
        }
        
        // Docker servisi kontrolü
        if (dockerManager->isDockerAvailable()) {
            qDebug() << "ApplicationStartup: Docker servisi çalışıyor.";
        } else {
            qWarning() << "ApplicationStartup: Docker servisi çalışmıyor veya erişilebilir değil!";
        }
        
        // Veritabanı bağlantısı kontrolü
        if (dbManager->connectToDatabase()) {
            qDebug() << "ApplicationStartup: Veritabanına bağlanıldı.";
        } else {
            qWarning() << "ApplicationStartup: Veritabanına bağlanılamadı!";
        }
        
    } catch (const std::exception& e) {
        qCritical() << "ApplicationStartup: Servis başlatma hatası:" << e.what();
    } catch (...) {
        qCritical() << "ApplicationStartup: Bilinmeyen servis başlatma hatası!";
    }
}

void ApplicationStartup::loadStyleSheets()
{
    qDebug() << "ApplicationStartup: Stil dosyaları yükleniyor...";
    
    if (!app) {
        qWarning() << "ApplicationStartup: QApplication referansı olmadan stiller yüklenemez!";
        return;
    }
    
    // Ana stil dosyasını yükle (qrc kaynaklarından)
    QFile styleFile(":/styles/styles/main.qss");
    
    if (styleFile.open(QFile::ReadOnly)) {
        QString styleSheet = QLatin1String(styleFile.readAll());
        app->setStyleSheet(styleSheet);
        
        qDebug() << "ApplicationStartup: Ana stil dosyası başarıyla yüklendi.";
        styleFile.close();
    } else {
        qWarning() << "ApplicationStartup: Stil dosyası açılamadı:" << styleFile.errorString();
    }
}

void ApplicationStartup::cleanup()
{
    qDebug() << "ApplicationStartup: Servisler temizleniyor...";
    
    // Singleton olmayan servis nesnelerini temizle
    // Not: Singleton servisler kendi kapanış mekanizmalarını kullanmalı
    
    // Şu an için özel bir temizleme gerektiren bir şey yok
    // Qt nesneleri parent-child ilişkisi sayesinde otomatik temizlenecek
}