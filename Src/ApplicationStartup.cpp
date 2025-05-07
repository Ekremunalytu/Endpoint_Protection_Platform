#include "../Headers/ApplicationStartup.h"
#include "../Headers/ServiceLocator.h"

// Tüm servis sınıflarının başlık dosyalarını dahil et
#include "../Headers/ApiManager.h"
#include "../Headers/YaraRuleManager.h"
#include "../Headers/CdrManager.h"
#include "../Headers/SandboxManager.h"
#include "../Headers/DbManager.h"
#include "../Headers/DockerManager.h"
#include "../Headers/ConfigManager.h"

#include <QDebug>

ApplicationStartup::ApplicationStartup(QObject *parent) : QObject(parent)
{
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
    
    qDebug() << "ApplicationStartup: Tüm servisler hazır.";
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
    
    // Özel servis oluşturma
    YaraRuleManager* yaraRuleManager = new YaraRuleManager();
    DbManager* dbManager = DbManager::getInstance();
    
    // Docker-tabanlı servisler için parent olarak bu sınıfı kullan
    DockerManager* dockerManager = new DockerManager(this);
    CdrManager* cdrManager = new CdrManager(this);
    SandboxManager* sandboxManager = new SandboxManager(this);
    
    // Tüm servisleri ServiceLocator'a kaydet
    ServiceLocator::provide(apiManager);
    ServiceLocator::provide(yaraRuleManager);
    ServiceLocator::provide(dbManager);
    ServiceLocator::provide(dockerManager);
    ServiceLocator::provide(cdrManager);
    ServiceLocator::provide(sandboxManager);
    
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

void ApplicationStartup::cleanup()
{
    qDebug() << "ApplicationStartup: Servisler temizleniyor...";
    
    // Singleton olmayan servis nesnelerini temizle
    // Not: Singleton servisler kendi kapanış mekanizmalarını kullanmalı
    
    // Şu an için özel bir temizleme gerektiren bir şey yok
    // Qt nesneleri parent-child ilişkisi sayesinde otomatik temizlenecek
}