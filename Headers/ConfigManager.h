#ifndef CONFIGMANAGER_H
#define CONFIGMANAGER_H

#include <QString>
#include <QSettings>
#include <QFile>
#include <QDir>
#include <QStandardPaths>
#include <QDebug>

class ConfigManager {
private:
    static ConfigManager* instance;
    QSettings* settings;
    QString configPath;

    ConfigManager() {
        // Uygulama veri dizininde config dosyası oluştur
        QString appDataPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir dir(appDataPath);
        if (!dir.exists()) {
            dir.mkpath(".");
        }
        configPath = appDataPath + "/config.ini";
        settings = new QSettings(configPath, QSettings::IniFormat);
    }

public:
    static ConfigManager* getInstance() {
        if (!instance) {
            instance = new ConfigManager();
        }
        return instance;
    }

    void setApiKey(const QString& key) {
        settings->setValue("api/key", key);
        settings->sync();
    }

    QString getApiKey() {
        return settings->value("api/key").toString();
    }

    bool hasApiKey() {
        return !settings->value("api/key").toString().isEmpty();
    }

    void clearApiKey() {
        settings->remove("api/key");
        settings->sync();
    }

    ~ConfigManager() {
        delete settings;
    }
};

#endif // CONFIGMANAGER_H 