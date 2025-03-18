#include "../Headers/HashCalculation.h"

QString HashCalculation::Md5Hashing(const QString &filePathMd5) {
    QString hashResult;
    try {
        // burada dosyanın açılıp açılmadığı kontrol ediliyor.
        QFile file(filePathMd5);
        if (!file.open(QIODevice::ReadOnly)) {
            throw QString("File does not exist!!");
        }

        QCryptographicHash Md5Hash(QCryptographicHash::Md5);
        if (!Md5Hash.addData(&file)) {
            throw QString("Hash calculation is failed! inline");
        }
        hashResult = Md5Hash.result().toHex();
    } catch (QString error) {
        qDebug() << "Error: " << error;
        return "";
    }
    return hashResult;
}
QString HashCalculation::Sha1Hashing(const QString &filePathSha1) {
    QString hashResult;
    try {
        QFile file(filePathSha1);
        if (!file.open(QIODevice::ReadOnly)) {
            throw QString("File does not exist!!");
        }
        QCryptographicHash Sha1Hash(QCryptographicHash::Sha1);
        if (!Sha1Hash.addData(&file)) {
            throw QString("Hash calculation failed!");
        }
        hashResult = Sha1Hash.result().toHex();
    } catch (QString error) {
        qDebug() << "Error: " << error;
        return "";
    }
    return hashResult;
}

QString HashCalculation::Sha256Hashing(const QString &filePathSha256) {
    QString hashResult;
    try {
        // burada dosyanın açılıp açılmadığı kontrol ediliyor.
        QFile file(filePathSha256);
        if (!file.open(QIODevice::ReadOnly)) {
            throw QString("File does not exist!!");
        }

        QCryptographicHash Sha256Hash(QCryptographicHash::Sha256);
        if (!Sha256Hash.addData(&file)) {
            throw QString("Hash calculation is failed! inline");
        }
        hashResult = Sha256Hash.result().toHex();
    } catch (QString error) {
        qDebug() << "Error: " << error;
        return "";
    }
    return hashResult;
}

QString HashCalculation::Sha512Hashing(const QString &filePathSha512) {
    QString hashResult;
    try {
        // burada dosyanın açılıp açılmadığı kontrol ediliyor.
        QFile file(filePathSha512);
        if (!file.open(QIODevice::ReadOnly)) {
            throw QString("File does not exist!!");
        }

        QCryptographicHash Sha512Hash(QCryptographicHash::Sha512);
        if (!Sha512Hash.addData(&file)) {
            throw QString("Hash calculation is failed! inline");
        }
        hashResult = Sha512Hash.result().toHex();
    } catch (QString error) {
        qDebug() << "Error: " << error;
        return "";
    }
    return hashResult;
}