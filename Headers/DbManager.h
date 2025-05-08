#ifndef DBMANAGER_H
#define DBMANAGER_H

#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QtCore/QFile>
#include <QtCore/QDebug>
#include <QtWidgets/QMessageBox>
#include <QtConcurrent>
#include <QtCore/QFutureWatcher>
#include <functional>
#include <mutex>
#include <memory>
#include "Interfaces/IDbManager.h"

// DatabaseManager sınıfı, veritabanı bağlantısı, şema oluşturma, tablo listeleme,
// örnek sorgu çalıştırma ve bağlantı kapatma işlemlerini yöneten bir singleton olarak çalışır
class DbManager : public IDbManager {
private:
    // Modern C++11 thread-safe singleton uygulaması
    static std::unique_ptr<DbManager> instance;
    static std::once_flag initInstanceFlag;
    static QSqlDatabase db;

    // Private constructor for singleton pattern
    DbManager();
    
    // Delete copy constructor and assignment operator
    DbManager(const DbManager&) = delete;
    DbManager& operator=(const DbManager&) = delete;
    
    // Veritabanı yardımcı fonksiyonları
    bool createTables();
    void closeConnection(const QString &connectionName = QString());

public:
    // Singleton pattern için modern thread-safe getInstance metodu
    static DbManager* getInstance();
    
    // Factory metodu ile shared_ptr döndüren alternatif
    static std::shared_ptr<DbManager> getInstanceShared();
    
    // Destructor
    ~DbManager();
    
    // IDbManager implementasyonu
    bool connectToDatabase() override;
    bool isDatabaseConnected() const override;
    void listTables() override;
    QString searchHashMd5(const QString &md5Hash) override;
    QString searchHashSha1(const QString &sha1) override;
    QString searchHashSha256(const QString &sha256) override;
    void executeSampleQuery() override;
    void asyncConnectToDatabase(std::function<void(bool)> callback) override;

    // Yardımcı sınıf metotları (static değil)
    bool addScanRecord(const QString &fileName, const QString &scanType, 
                      const QString &md5Hash, const QString &sha1Hash, 
                      const QString &sha256Hash, bool isDetected,
                      const QString &detectionDetails);
    QStringList getRecentScans(int limit = 10);
};

#endif // DBMANAGER_H
