#ifndef IDBMANAGER_H
#define IDBMANAGER_H

#include <QString>
#include <QStringList>
#include <functional>

// Veritabanı yönetimi için soyut arayüz
class IDbManager {
public:
    virtual ~IDbManager() = default;
    
    virtual bool connectToDatabase() = 0;
    virtual bool isDatabaseConnected() const = 0;
    virtual void listTables() = 0;
    virtual QString searchHashMd5(const QString &md5Hash) = 0;
    virtual QString searchHashSha1(const QString &sha1) = 0;
    virtual QString searchHashSha256(const QString &sha256) = 0;
    virtual void executeSampleQuery() = 0;
    virtual void asyncConnectToDatabase(std::function<void(bool)> callback) = 0;
};

#endif // IDBMANAGER_H