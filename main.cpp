#include <iostream>
#include <QCoreApplication>
#include "HashCalculation.h"
int main(int argc, char *argv[]) {

        QCoreApplication app(argc, argv);

        QString file_Path = "/Volumes/Crucial/Endpoint_Protection_Platform/test.txt";

        try {
                QString md5value = HashCalculation::Md5Hashing(file_Path);
                QString sha256value = HashCalculation::Sha256Hashing(file_Path);
                QString sha512value = HashCalculation::Sha512Hashing(file_Path);

                std::cout << "MD5 hash: " << md5value.toStdString() << std::endl;
                std::cout << "SHA256 hash: " << sha256value.toStdString() << std::endl;
                std::cout << "SHA512 hash: " << sha512value.toStdString() << std::endl;

        } catch (QString error) {
                std::cerr << error.toStdString() << std::endl;
        }




        return app.exec();
}
