#include <QApplication>
#include <iostream>
#include "Headers/DbManager.h"
#include "Headers/HashCalculation.h"
#include "Headers/UserInterface.h"  // Örneğin, GUI için UserInterface veya MainWindow

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Veritabanı bağlantısını kur.
    QString dbPath = "hash.db";
    if (!DbManager::connectToDatabase(dbPath)) {
        return -1;
    }

    // Mevcut tabloları listele.
    DbManager::listTables();


    // Örnek sorgu çalıştır.
    DbManager::executeSampleQuery();

    // Dosya hash hesaplamaları (HashCalculation modülünü kullanıyoruz)
    try {
        QString filePath = "/Volumes/Crucial/Endpoint_Protection_Platform/test.txt";
        QString md5value = HashCalculation::Md5Hashing(filePath);
        QString sha256value = HashCalculation::Sha256Hashing(filePath);
        QString sha512value = HashCalculation::Sha512Hashing(filePath);

        std::cout << "MD5 hash: " << md5value.toStdString() << std::endl;
        std::cout << "SHA256 hash: " << sha256value.toStdString() << std::endl;
        std::cout << "SHA512 hash: " << sha512value.toStdString() << std::endl;
    } catch (const QString &error) {
        std::cerr << "Error: " << error.toStdString() << std::endl;
    }

    // Kullanıcı arayüzü penceresini oluştur ve göster.
    MainWindow mainWindow;
    mainWindow.show();

    // Uygulama olay döngüsünü başlat.
    int result = app.exec();

    // Uygulama kapanmadan önce veritabanı bağlantısını kapat.
    //DbManager::closeConnection();

    return result;
}
