
#ifndef HASHCALCULATION_H
#define HASHCALCULATION_H

#include <QString>
#include <QCryptographicHash>
#include <QFile>
#include <QDebug>

class HashCalculation {
public:
    static QString Md5Hashing(const QString &filePathMd5);
    static QString Sha256Hashing(const QString &filePathSha256);
    static QString Sha512Hashing(const QString &filePathSha512);

};

#endif //HASHCALCULATION_H
