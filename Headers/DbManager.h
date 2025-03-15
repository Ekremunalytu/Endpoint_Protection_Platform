#ifndef DbManager_H
#define DbManager_H

#include <QString>
#include <QStringList>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QFile>
#include <QDebug>

// DatabaseManager sınıfı, veritabanı bağlantısı, şema oluşturma, tablo listeleme,
// örnek sorgu çalıştırma ve bağlantı kapatma işlemlerini yöneten static metodları içerir.
class DbManager {
public:
    // SQLite veritabanına bağlanır.
    static bool connectToDatabase(const QString &dbPath);

    // Veritabanındaki tabloları listeler.
    static void listTables();

    // Belirtilen şema dosyasını çalıştırarak veritabanı yapısını oluşturur.
    // Şema oluşturma, veritabanında gerekli "FILE" tablosu yoksa gerçekleştirilir.
    static bool applySchemaFromFile(const QString &schemaFilePath);

    // 'FILE' tablosundan örnek sorgu çalıştırır.
    static void executeSampleQuery();

    // Veritabanı bağlantısını kapatır ve bağlantıyı havuzdan kaldırır.
    static void closeConnection(const QString &connectionName = QSqlDatabase::defaultConnection);
};

#endif DbManager_H
