#include "../Headers/ConfigManager.h"

// Static üyelerin tanımlanması
ConfigManager* ConfigManager::instance = nullptr;
std::mutex ConfigManager::mutex;

// Not: Header dosyasında inline tanımlanmış metotlar burada tekrar tanımlanmayacak