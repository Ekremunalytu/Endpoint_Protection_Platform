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

bool DbManager::applySchemaFromFile(const QString &schemaFilePath) {
    // Eğer veritabanında "FILE" tablosu zaten varsa, şema uygulanmaz.
    QSqlDatabase db = QSqlDatabase::database();
    if (db.tables().contains("FILE")) {
        qDebug() << "Table 'FILE' exists. Skipping schema creation.";
        return true;
    }

    QFile file(schemaFilePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qDebug() << "Schema file could not be opened:" << file.errorString();
        return false;
    }
    QString schemaSql = file.readAll();
    file.close();

    QSqlQuery query;
    // Şemadaki birden fazla SQL komutunu noktalı virgülle ayırıyoruz.
    QStringList commands = schemaSql.split(';', Qt::SkipEmptyParts);
    for (QString command : commands) {
        command = command.trimmed();
        if (!command.isEmpty()) {
            if (!query.exec(command)) {
                qDebug() << "Failed to execute schema command:" << command;
                qDebug() << "Error:" << query.lastError().text();
                return false;
            }
        }
    }
    qDebug() << "Schema applied successfully.";
    return true;
}

void DbManager::executeSampleQuery() {
    QSqlQuery query;
    if (!query.exec("SELECT * FROM FILE LIMIT 10;")) {
        qDebug() << "Query failed:" << query.lastError().text();
        return;
    }
    while (query.next()) {
        QString hash = query.value("hash").toString();
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
