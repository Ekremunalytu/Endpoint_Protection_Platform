#ifndef APPLICATIONSTARTUP_H
#define APPLICATIONSTARTUP_H

#include <QObject>

// Servis sağlayıcı sınıf
class ApplicationStartup : public QObject
{
    Q_OBJECT

public:
    explicit ApplicationStartup(QObject *parent = nullptr);
    ~ApplicationStartup();

    // Uygulamayı başlat ve tüm servisleri hazırla
    void initialize();
    
    // Servis sağlayıcılarını temizle
    void cleanup();

private:
    // Servisleri başlat
    void initializeServices();
    void registerServices();
};

#endif // APPLICATIONSTARTUP_H