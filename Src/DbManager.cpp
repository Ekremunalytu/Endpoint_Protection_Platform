#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QThread>
#include "../Headers/DbManager.h"

// Modern singleton için static üye tanımlamaları
std::unique_ptr<DbManager> DbManager::instance = nullptr;
std::once_flag DbManager::initInstanceFlag;
QSqlDatabase DbManager::db;

// Private constructor implementation
DbManager::DbManager() {
    // Constructor içi boş kalabilir veya gerekli başlangıç işlemleri yapılabilir
}

// Destructor implementation - temizlik işlemleri
DbManager::~DbManager() {
    // Eğer instance nesnesi yok olurken açık veritabanı bağlantıları varsa kapatılmalı
    QStringList connectionNames = QSqlDatabase::connectionNames();
    for (const QString& connectionName : connectionNames) {
        closeConnection(connectionName);
    }
}

// Modern C++11 singleton pattern için thread-safe getInstance metodu
DbManager* DbManager::getInstance() {
    std::call_once(initInstanceFlag, []() {
        instance = std::unique_ptr<DbManager>(new DbManager());
    });
    return instance.get();
}

// Shared_ptr döndüren alternatif getInstance metodu
std::shared_ptr<DbManager> DbManager::getInstanceShared() {
    static std::shared_ptr<DbManager> sharedInstance = nullptr;
    
    if (!sharedInstance) {
        DbManager* rawInstance = getInstance();
        // Raw pointer'ı shared_ptr'ye dönüştürüyoruz, ancak instance'ın sahipliğini almıyoruz
        sharedInstance = std::shared_ptr<DbManager>(rawInstance, [](DbManager*) {
            // Boş deleter - gerçek nesne unique_ptr tarafından yönetiliyor
        });
    }
    
    return sharedInstance;
}

// Thread local veritabanı bağlantı adını oluştur
QString getConnectionNameForThread() {
    return QString("connection_%1").arg((quintptr)QThread::currentThreadId());
}

bool DbManager::connectToDatabase() {
    // 1. Önce çalıştırılabilir dosya dizininde arayalım (build dizini)
    QString exePath = QCoreApplication::applicationDirPath();
    QString dbPath = QDir::toNativeSeparators(exePath + "/MalwareHashes/identifier.sqlite");
    
    // Dosya varlığını kontrol et
    QFileInfo checkFile(dbPath);
    if (!checkFile.exists() || !checkFile.isFile()) {
        // 2. Eğer bulamazsak, proje kök dizinine göre arayalım
        QString projectPath = QDir(exePath).absolutePath();
        
        // Windows'ta build/Release/.. veya Mac'te build/.. şeklinde olabilir, üst dizinleri kontrol edelim
        if (projectPath.contains("build")) {
            QDir dir(projectPath);
            // Build dizininden üst dizine çıkalım
            dir.cdUp();
            
            // Release dizini varsa bir üst dizine daha çıkalım (Windows için)
            if (projectPath.contains("Release")) {
                dir.cdUp();
            }
            
            // Şimdi proje kök dizinindeyiz, MalwareHashes klasörüne bakalım
            dbPath = QDir::toNativeSeparators(dir.absolutePath() + "/MalwareHashes/identifier.sqlite");
            checkFile.setFile(dbPath);
            
            if (!checkFile.exists() || !checkFile.isFile()) {
                qDebug() << "Veritabanı dosyası bulunamadı:" << dbPath;
                return false;
            }
        }
    }
    
    qDebug() << "Using database at:" << dbPath;
    
    // Thread için benzersiz bir bağlantı adı oluşturuyoruz
    QString connectionName = getConnectionNameForThread();
    
    // Eğer bu thread için zaten bir bağlantı varsa, onu kapatıp yeniden açalım
    if (QSqlDatabase::contains(connectionName)) {
        QSqlDatabase::removeDatabase(connectionName);
    }
    
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", connectionName);
    db.setDatabaseName(dbPath);
    if (!db.open()) {
        qDebug() << "Database connection failed:" << db.lastError().text();
        return false;
    }
    qDebug() << "Connected to SQLite database successfully with Qt! Connection:" << connectionName;
    return true;
}

void DbManager::listTables() {
    QSqlDatabase db = QSqlDatabase::database(getConnectionNameForThread());
    if (!db.isOpen()) {
        qDebug() << "Database not open for listing tables";
        return;
    }
    QStringList tables = db.tables();
    qDebug() << "Tables in the database:" << tables;
}

QString DbManager::searchHashMd5(const QString &md5Hash) {
    QString connectionName = getConnectionNameForThread();
    if (!QSqlDatabase::contains(connectionName) || !QSqlDatabase::database(connectionName).isOpen()) {
        if (!connectToDatabase()) {
            return QString("Database connection failed");
        }
    }
    
    QSqlDatabase db = QSqlDatabase::database(connectionName);
    QSqlQuery query(db);
    query.prepare("SELECT md5 FROM md5_hashes WHERE md5 = :md5_hash");
    query.bindValue(":md5_hash", md5Hash);

    if (!query.exec()) {
        qDebug() << "Query failed:" << query.lastError().text();
        return QString("Query execution failed.");
    }
    if (query.next()) {
        QMessageBox::warning(nullptr, "Alert!!!","Malicious hash signature detected!!!");
        return QString("Alert!!, Malicious hash signature detected!!!");
    }

    return QString();
}

QString DbManager::searchHashSha1(const QString &sha1) {
    QString connectionName = getConnectionNameForThread();
    if (!QSqlDatabase::contains(connectionName) || !QSqlDatabase::database(connectionName).isOpen()) {
        if (!connectToDatabase()) {
            return QString("Database connection failed");
        }
    }
    
    QSqlDatabase db = QSqlDatabase::database(connectionName);
    QSqlQuery query(db);
    query.prepare("SELECT sha1 FROM sha1_hashes WHERE sha1 = :sha1_hash");
    query.bindValue(":sha1_hash", sha1);

    if (!query.exec()) {
        qDebug() << "Query failed:" << query.lastError().text();
        return QString("Query execution failed.");
    }
    if (query.next()) {
        QMessageBox::warning(nullptr, "Alert!!!","Malicious hash signature detected!!!");
        return QString("Alert!!, Malicious hash signature detected!!!");
    }

    return QString();
}

QString DbManager::searchHashSha256(const QString &sha256) {
    QString connectionName = getConnectionNameForThread();
    if (!QSqlDatabase::contains(connectionName) || !QSqlDatabase::database(connectionName).isOpen()) {
        if (!connectToDatabase()) {
            return QString("Database connection failed");
        }
    }
    
    QSqlDatabase db = QSqlDatabase::database(connectionName);
    QSqlQuery query(db);
    query.prepare("SELECT sha256 FROM sha256_hashes WHERE sha256 = :sha256_hash");
    query.bindValue(":sha256_hash", sha256);

    if (!query.exec()) {
        qDebug() << "Query failed:" << query.lastError().text();
        return QString("Query execution failed.");
    }
    if (query.next()) {
        QMessageBox::warning(nullptr, "Alert!!!","Malicious hash signature detected!!!");
        return QString("Alert!!, Malicious hash signature detected!!!");
    }

    return QString();
}

void DbManager::executeSampleQuery() {
    QString connectionName = getConnectionNameForThread();
    if (!QSqlDatabase::contains(connectionName) || !QSqlDatabase::database(connectionName).isOpen()) {
        if (!connectToDatabase()) {
            qDebug() << "Database connection failed";
            return;
        }
    }
    
    QSqlDatabase db = QSqlDatabase::database(connectionName);
    QSqlQuery query(db);
    if (!query.exec("SELECT * FROM md5_hashes LIMIT 10;")) {
        qDebug() << "Query failed:" << query.lastError().text();
        return;
    }
    while (query.next()) {
        QString hash = query.value("md5").toString();
        qDebug() << "Hash:" << hash;
    }
}

void DbManager::closeConnection(const QString &connectionName) {
    QString connName = connectionName.isEmpty() ? getConnectionNameForThread() : connectionName;
    
    if (QSqlDatabase::contains(connName)) {
        QSqlDatabase db = QSqlDatabase::database(connName);
        if (db.isOpen()) {
            db.close();
        }
        // Bağlantıyı havuzdan kaldırıyoruz.
        QSqlDatabase::removeDatabase(connName);
        qDebug() << "Database connection closed and removed:" << connName;
    }
}

void DbManager::asyncConnectToDatabase(std::function<void(bool)> callback) {
    // Capture this pointer in the lambda so we can access connectToDatabase()
    QFuture<bool> future = QtConcurrent::run([this]() {
        return connectToDatabase();
    });
    QFutureWatcher<bool>* watcher = new QFutureWatcher<bool>();
    QObject::connect(watcher, &QFutureWatcher<bool>::finished, [watcher, future, callback]() mutable {
        callback(future.result());
        watcher->deleteLater();
    });
    watcher->setFuture(future);
}

// Veritabanı bağlantısının açık olup olmadığını kontrol eder.
bool DbManager::isDatabaseConnected() const {
    QString connectionName = getConnectionNameForThread();
    if (QSqlDatabase::contains(connectionName)) {
        QSqlDatabase db = QSqlDatabase::database(connectionName);
        return db.isOpen();
    }
    return false;
}
