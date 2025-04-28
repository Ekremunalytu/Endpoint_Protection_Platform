#ifndef DbManager_H
#define DbManager_H

#include <QString>
#include <QStringList>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QFile>
#include <QDebug>
#include <QMessageBox>
#include <QtConcurrent>
#include <QFutureWatcher>

// DatabaseManager sınıfı, veritabanı bağlantısı, şema oluşturma, tablo listeleme,
// örnek sorgu çalıştırma ve bağlantı kapatma işlemlerini yöneten static metodları içerir.
class DbManager {
public:
    // SQLite veritabanına bağlanır.
    static bool connectToDatabase();

    // Veritabanındaki tabloları listeler.
    static void listTables();

    static QString searchHashmMd5(const QString &md5Hash);

    static QString searchHashSha_1(QString sha1);

    static QString searchHashSha_256(QString sha256);


    // 'FILE' tablosundan örnek sorgu çalıştırır.
    static void executeSampleQuery();

    // Veritabanı bağlantısını kapatır ve bağlantıyı havuzdan kaldırır.
    static void closeConnection(const QString &connectionName = QSqlDatabase::defaultConnection);

    // Asenkron veritabanı bağlantısı (threaded)
    static void asyncConnectToDatabase(std::function<void(bool)> callback);
};

#endif // DbManager_H
