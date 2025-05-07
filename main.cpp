#include <QApplication>
#include "Headers/UserInterface.h"
#include "Headers/ApplicationStartup.h"
#include "Headers/ServiceLocator.h"
#include "Headers/DbManager.h"
#include <QDebug>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    qDebug() << "Uygulama başlatılıyor...";
    
    // Uygulama başlatıcısını oluştur ve servisleri başlat
    ApplicationStartup* appStartup = new ApplicationStartup(&app);
    appStartup->initialize();
    
    // Veritabanı bağlantısı başarılı olduğunda ana pencereyi göster
    IDbManager* dbManager = ServiceLocator::getDbManager();
    
    if (dbManager && dbManager->isDatabaseConnected()) {
        qDebug() << "Veritabanı bağlantısı başarılı, ana pencere oluşturuluyor...";
        
        MainWindow* mainWindow = new MainWindow();
        mainWindow->show();
        mainWindow->setWindowState(Qt::WindowMaximized);
        mainWindow->setWindowTitle("Endpoint Protection Platform");
    } else {
        qCritical() << "Veritabanı bağlantısı başarısız, uygulama kapatılıyor!";
        QMessageBox::critical(nullptr, "Bağlantı Hatası",
                            "Veritabanına bağlanılamadı!\n"
                            "Lütfen veritabanı ayarlarınızı kontrol edin.");
        return -1;
    }
    
    return app.exec();
}
