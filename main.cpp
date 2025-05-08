#include <QApplication>
#include "Database/Headers/DbManager.h"
#include "Core/Headers/HashCalculation.h"
#include "UI/Headers/MainWindow.h"
#include "Core/Headers/ApplicationStartup.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    // First initialize the database
    DbManager::getInstance()->asyncConnectToDatabase([&app](bool success) {
        if (!success) {
            app.exit(-1);
            return;
        }
        
        // After database connection, initialize all services properly
        ApplicationStartup* startup = new ApplicationStartup(&app);
        startup->initialize();
        
        // Only after services are properly initialized and registered, create the UI
        MainWindow* mainWindow = new MainWindow();
        mainWindow->show();
        mainWindow->setWindowState(Qt::WindowMaximized);
        mainWindow->setWindowTitle("Endpoint Protection Platform");
    });
    
    return app.exec();
}
