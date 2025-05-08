#include "../Headers/ConfigManager.h"
#include <QSettings>
#include <QDir>
#include <QStandardPaths>

// Static üyelerin tanımlanması
ConfigManager* ConfigManager::instance = nullptr;
std::mutex ConfigManager::mutex;