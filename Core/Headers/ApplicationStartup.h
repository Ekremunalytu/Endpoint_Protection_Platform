#ifndef APPLICATIONSTARTUP_H
#define APPLICATIONSTARTUP_H

#include <QObject>
#include <QApplication>

// Servis sağlayıcı sınıf
class ApplicationStartup : public QObject
{
    Q_OBJECT

public:
    explicit ApplicationStartup(QObject *parent = nullptr);
    ~ApplicationStartup();

    // Uygulamayı başlat ve tüm servisleri hazırla
    void initialize();

private:
    // Servisleri başlat
    void initializeServices();
    void registerServices();
    void loadStyleSheets();  // Stil dosyalarını yüklemek için yeni fonksiyon
    void cleanup();

    QApplication* app;  // QApplication referansı için pointer
};

#endif // APPLICATIONSTARTUP_H