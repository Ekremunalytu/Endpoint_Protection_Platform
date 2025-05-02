#include <QApplication>
#include "Headers/DbManager.h"
#include "Headers/HashCalculation.h"
#include "Headers/UserInterface.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    DbManager::asyncConnectToDatabase([&](bool success) {
        if (!success) {
            app.exit(-1);
            return;
        }
        MainWindow* mainWindow = new MainWindow();
        mainWindow->show();
        mainWindow->setWindowState(Qt::WindowFullScreen);
        mainWindow->setWindowTitle("Windows Antivirus");
    });
    return app.exec();
}
