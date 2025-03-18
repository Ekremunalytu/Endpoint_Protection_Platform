#include <QApplication>
#include "Headers/DbManager.h"
#include "Headers/HashCalculation.h"
#include "Headers/UserInterface.h"

int main(int argc, char *argv[]) {
    // macOS'ta menü çubuğunun pencere içinde kalmasını sağlamak için:
    QApplication::setAttribute(Qt::AA_DontUseNativeMenuBar, true);

    QApplication app(argc, argv);

    // Veritabanı bağlantısını kur
    QString dbPath = "/Volumes/Crucial/WindowsAv/MalwareHashes/identifier.sqlite";
    if (!DbManager::connectToDatabase(dbPath)) {
        return -1;
    }

    // Ana pencere (MainWindow)
    MainWindow mainWindow;
    // Tam ekran başlat
    mainWindow.showFullScreen();

    return app.exec();
}
