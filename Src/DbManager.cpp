#include "../Headers/DbManager.h"

bool DbManager::connectToDatabase(const QString &dbPath) {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);
    if (!db.open()) {
        qDebug() << "Database connection failed:" << db.lastError().text();
        return false;
    }
    qDebug() << "Connected to SQLite database successfully with Qt!";
    return true;
}

void DbManager::listTables() {
    QSqlDatabase db = QSqlDatabase::database();
    QStringList tables = db.tables();
    qDebug() << "Tables in the database:" << tables;
}

QString DbManager::searchHashmMd5(const QString &md5Hash) {
    QSqlQuery query;
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

QString DbManager::searchHashSha_1(QString sha1) {
    QSqlQuery query;
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

QString DbManager::searchHashSha_256(QString sha256) {
    QSqlQuery query;
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
    QSqlQuery query;
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
    QSqlDatabase db = QSqlDatabase::database(connectionName);
    if (db.isOpen()) {
        db.close();
    }
    // Bağlantıyı havuzdan kaldırıyoruz.
    QSqlDatabase::removeDatabase(connectionName);
    qDebug() << "Database connection closed and removed.";
}
