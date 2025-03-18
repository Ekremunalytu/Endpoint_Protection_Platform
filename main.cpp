#include <QApplication>
#include "Headers/DbManager.h"
#include "Headers/HashCalculation.h"
#include "Headers/UserInterface.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    // Yeni proje database dizini
    QString dbPath = "/Volumes/Crucial/WindowsAv/MalwareHashes/identifier.sqlite";
    if (!DbManager::connectToDatabase(dbPath)) {
        return -1;
    }

    MainWindow mainWindow;
    // mainWindow.showFullScreen(); // Zaten ctor'da showFullScreen() var ise gerek yok
    mainWindow.show(); // Eğer constructor içinde tam ekran açıyorsanız, show() da ekleyebilirsiniz

    return app.exec();
}
