#include <QtWidgets/QApplication>

#include "Headers/ApiManager.h"
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

    ApiManager apiManager;

    QString apiresponse;
    apiManager.sendHashToVirusTotal("598d4c200461b81522a3328565c25f7c", apiresponse);
    //apiManager.sendFileToVirusTotal();

    MainWindow mainWindow;
    // mainWindow.showFullScreen(); // Zaten ctor'da showFullScreen() var ise gerek yok
    mainWindow.show(); // Eğer constructor içinde tam ekran açıyorsanız, show() da ekleyebilirsiniz

    return app.exec();
}
