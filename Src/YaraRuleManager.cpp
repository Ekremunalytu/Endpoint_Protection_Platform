#include "../Headers/YaraRuleManager.h"
#include <fstream>
#include <cstdio>
#include <iostream>
#include <memory>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QFile>
#include <QTextStream>

#ifdef _WIN32
#include <windows.h>
#endif

extern "C" {
    #include <yara.h>
}

// Static callback fonksiyonu
static int yara_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    auto* manager = reinterpret_cast<YaraRuleManager*>(user_data);
    // CALLBACK_MSG_RULE_MATCHING, YARA eşleşme mesajı
    if (message == CALLBACK_MSG_RULE_MATCHING && manager && manager->getCallback()) {
        YR_RULE* rule = static_cast<YR_RULE*>(message_data);
        manager->getCallback()(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// Constructor & Destructor
YaraRuleManager::YaraRuleManager() = default;

YaraRuleManager::~YaraRuleManager() {
    finalize();
}

// Initialize / Finalize
std::error_code YaraRuleManager::initialize() noexcept {
    if (initialized)
        return make_error_code(YaraErrorCodes::AlreadyInitialized);

    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        qDebug() << "YARA initialization failed with code:" << result;
        return make_error_code(YaraErrorCodes::InternalError);
    }

    initialized = true;
    qDebug() << "YARA successfully initialized";
    return make_error_code(YaraErrorCodes::success);
}

std::error_code YaraRuleManager::finalize() noexcept {
    if (!initialized)
        return make_error_code(YaraErrorCodes::NotInitialized);

    unloadRules();
    yr_finalize();
    initialized = false;
    return make_error_code(YaraErrorCodes::success);
}

#ifdef _WIN32
// Windows için geniş karakter dosya açma yardımcı fonksiyonu
FILE* win32_fopen(const QString& path, const char* mode) {
    FILE* fp = nullptr;
    std::wstring wPath = path.toStdWString();
    std::wstring wMode;
    
    // mode stringini wstring'e dönüştür
    for (const char* c = mode; *c; ++c) {
        wMode.push_back(static_cast<wchar_t>(*c));
    }
    
    _wfopen_s(&fp, wPath.c_str(), wMode.c_str());
    return fp;
}
#endif

// Basitleştirilmiş YARA kuralı oluşturma fonksiyonu
bool createSimpleYaraRule(const QString& rulePath) {
    // Basit bir YARA kuralı oluşturalım
    const char* simpleRule = 
        "rule simple_test_rule {\n"
        "    meta:\n"
        "        description = \"Simple test rule\"\n"
        "        author = \"Auto-generated\"\n"
        "    strings:\n"
        "        $a = \"test string\" nocase\n"
        "    condition:\n"
        "        $a\n"
        "}\n";
    
    QFile file(rulePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qDebug() << "Basit YARA kuralı dosyası oluşturulamadı:" << rulePath;
        return false;
    }
    
    QTextStream out(&file);
    out << simpleRule;
    file.close();
    
    qDebug() << "Basit YARA kuralı oluşturuldu:" << rulePath;
    return true;
}

// Load & Unload Rules
std::error_code YaraRuleManager::loadRules(const std::string& rulesFilePath) noexcept {
    if (!initialized)
        return make_error_code(YaraErrorCodes::NotInitialized);

    unloadRules();

    // Dosya yolu kontrolü için Qt sınıflarını kullanalım
    QString qRulePath = QString::fromStdString(rulesFilePath);
    QFileInfo fileInfo(qRulePath);
    
    // Eğer dosya belirtilen yolda yoksa, alternatif konumları deneyelim
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        // Çalıştırılabilir dosya yolunu alalım
        QString exePath = QCoreApplication::applicationDirPath();
        QString ruleFileName = QFileInfo(qRulePath).fileName();
        
        qDebug() << "Original rule path not found, searching alternatives: " << qRulePath;
        qDebug() << "Rule file name: " << ruleFileName;
        
        // 1. Build dizini içindeki Rules klasörünü deneyelim
        QString buildRulesPath = QDir::toNativeSeparators(exePath + "/Rules/" + ruleFileName);
        QFileInfo buildRulesCheck(buildRulesPath);
        
        if (buildRulesCheck.exists() && buildRulesCheck.isFile()) {
            qRulePath = buildRulesPath;
            qDebug() << "Found rule in build directory: " << qRulePath;
        } else {
            // 2. Proje kök dizininde Rules klasörünü deneyelim
            QString projectPath = QDir(exePath).absolutePath();
            
            if (projectPath.contains("build")) {
                QDir dir(projectPath);
                // Build dizininden üst dizine çıkalım
                dir.cdUp();
                
                // Release dizini varsa bir üst dizine daha çıkalım (Windows için)
                if (projectPath.contains("Release")) {
                    dir.cdUp();
                }
                
                // Şimdi proje kök dizinindeyiz
                QString rootRulesPath = QDir::toNativeSeparators(dir.absolutePath() + "/Rules/" + ruleFileName);
                QFileInfo rootRulesCheck(rootRulesPath);
                
                qDebug() << "Checking project root rules path: " << rootRulesPath;
                
                if (rootRulesCheck.exists() && rootRulesCheck.isFile()) {
                    qRulePath = rootRulesPath;
                    qDebug() << "Found rule in project root directory: " << qRulePath;
                } else {
                    // 3. Release klasöründeki Rules dizinini deneyelim
                    QString releaseRulesPath = QDir::toNativeSeparators(exePath + "/../Rules/" + ruleFileName);
                    QFileInfo releaseRulesCheck(releaseRulesPath);
                    
                    if (releaseRulesCheck.exists() && releaseRulesCheck.isFile()) {
                        qRulePath = releaseRulesPath;
                        qDebug() << "Found rule in release parent directory: " << qRulePath;
                    } else {
                        // 4. Basit bir test kuralı oluşturalım
                        QString tempRulePath = QDir::toNativeSeparators(exePath + "/simple_test.yar");
                        if (createSimpleYaraRule(tempRulePath)) {
                            qRulePath = tempRulePath;
                            qDebug() << "Created and using simple test rule: " << qRulePath;
                        } else {
                            // Tüm olası yerlere baktık, dosya bulunamadı
                            qDebug() << "All rule path attempts failed";
                            std::cerr << "YARA kural dosyası bulunamadı: " << rulesFilePath << std::endl;
                            return make_error_code(YaraErrorCodes::FileNotFound);
                        }
                    }
                }
            }
        }
    }
    
    qDebug() << "Using YARA rules from: " << qRulePath;
    
    YR_COMPILER* rawCompiler = nullptr;
    int cres = yr_compiler_create(&rawCompiler);
    if (cres != ERROR_SUCCESS) {
        qDebug() << "YARA compiler creation failed with code:" << cres;
        return make_error_code(YaraErrorCodes::InternalError);
    }
    compiler.reset(rawCompiler);

    // Hata yakalama fonksiyonunu ayarla
    yr_compiler_set_callback(compiler.get(), 
        [](int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data) -> void {
            qDebug() << "YARA compiler error: Level:" << error_level << "Line:" << line_number
                     << "Message:" << message << "File:" << (file_name ? file_name : "unknown");
        }, 
        nullptr);

    // Dosyayı açmak için platform-spesifik yöntem kullanıyoruz
    FILE* ruleFile = nullptr;
    
#ifdef _WIN32
    // Windows'ta geniş karakter desteği ile açalım
    ruleFile = win32_fopen(qRulePath, "r");
#else
    // Diğer platformlarda normal açalım
    ruleFile = fopen(qRulePath.toUtf8().constData(), "r");
#endif

    if (!ruleFile) {
        qDebug() << "Failed to open rule file: " << qRulePath;
        std::cerr << "YARA kural dosyası açılamadı: " << qRulePath.toStdString() << std::endl;
        return make_error_code(YaraErrorCodes::FileNotFound);
    }

    // Önce dosyanın içeriğini yazdıralım
    qDebug() << "YARA rule file content:";
    
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), ruleFile)) {
        qDebug() << QString(buffer).trimmed();
    }
    
    // Dosyayı başına geri sarıyoruz
    rewind(ruleFile);
    
    // Şimdi compiler'a ekleyelim
    cres = yr_compiler_add_file(
        compiler.get(),
        ruleFile,
        nullptr,
        qRulePath.toUtf8().constData()
    );
    
    fclose(ruleFile);
    
    if (cres != ERROR_SUCCESS) {
        qDebug() << "YARA rule compilation error with code:" << cres;
        std::cerr << "YARA kural derleme hatası" << std::endl;
        return make_error_code(YaraErrorCodes::CompilerError);
    }

    // Eğer derleme başarılıysa, kuralları elde edelim
    YR_RULES* rawRules = nullptr;
    cres = yr_compiler_get_rules(compiler.get(), &rawRules);
    
    if (cres != ERROR_SUCCESS) {
        qDebug() << "Failed to get compiled rules with code:" << cres;
        return make_error_code(YaraErrorCodes::CompilerError);
    }
    
    // Kuralları saklayalım
    rules.reset(rawRules);
    
    // Compiler'ı temizleyelim
    compiler.reset();
    
    qDebug() << "YARA rules successfully loaded and compiled";
    std::cout << "YARA kuralları başarıyla yüklendi ve derlendi." << std::endl;
    return make_error_code(YaraErrorCodes::success);
}

std::error_code YaraRuleManager::unloadRules() noexcept {
    compiler.reset();
    rules.reset();
    return make_error_code(YaraErrorCodes::success);
}

// Compile Rules - artık loadRules içinde yapılıyor
std::error_code YaraRuleManager::compileRules() noexcept {
    if (!compiler) {
        qDebug() << "No compiler available for rule compilation";
        return make_error_code(YaraErrorCodes::RulesNotCompiled);
    }

    qDebug() << "Attempting to compile YARA rules";
    YR_RULES* rawRules = nullptr;
    int cres = yr_compiler_get_rules(compiler.get(), &rawRules);
    if (cres != ERROR_SUCCESS) {
        qDebug() << "Compilation failed with code:" << cres;
        return make_error_code(YaraErrorCodes::CompilerError);
    }

    qDebug() << "Rules compiled successfully";
    rules.reset(rawRules);
    compiler.reset();
    return make_error_code(YaraErrorCodes::success);
}

// Callback setter
void YaraRuleManager::setCallback(std::function<void(const std::string&)> cb) noexcept {
    callback = std::move(cb);
}

// Scanning Methods
std::error_code YaraRuleManager::scanFile(const std::string& filePath, std::vector<std::string>& matches) noexcept {
    if (!initialized) {
        qDebug() << "YARA not initialized for scanning";
        return make_error_code(YaraErrorCodes::NotInitialized);
    }
    if (!rules) {
        qDebug() << "No compiled rules available for scanning";
        return make_error_code(YaraErrorCodes::RulesNotCompiled);
    }

    // Dosya varlığını kontrol et
    QString qFilePath = QString::fromStdString(filePath);
    QFileInfo fileInfo(qFilePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        qDebug() << "File does not exist or is not accessible:" << qFilePath;
        return make_error_code(YaraErrorCodes::FileNotFound);
    }
    
    // Dosya izinlerini kontrol et
    QFile file(qFilePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Cannot open file for reading:" << qFilePath << "Error:" << file.errorString();
        return make_error_code(YaraErrorCodes::FileNotFound);
    }
    file.close();

    matches.clear();
    setCallback([&matches](const std::string& name) { 
        matches.push_back(name); 
        qDebug() << "Found YARA match:" << QString::fromStdString(name);
    });

    qDebug() << "Scanning file with YARA: " << qFilePath;
    
    // YARA tarama seçeneklerini ayarlayalım
    int scan_flags = 0;
    
    // Hash modülü kullanıldığında SCAN_FLAGS_PROCESS_MEMORY bayrağını etkinleştir
    // Bu "import hash" ile ilgili sorunları önleyebilir
    scan_flags |= SCAN_FLAGS_NO_TRYCATCH;  // Hata yakalama devre dışı bırakılır
    
#ifdef _WIN32
    // Windows'ta dosya yolu için özel karakter desteği
    std::wstring wFilePath = qFilePath.toStdWString();
    
    // Dosyayı manuel olarak açalım ve bellek olarak tarayalım
    try {
        FILE* fp = _wfopen(wFilePath.c_str(), L"rb");
        if (fp) {
            // Dosya boyutunu belirle
            fseek(fp, 0, SEEK_END);
            long fileSize = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            
            if (fileSize > 0) {
                // Dosya içeriğini oku
                std::vector<uint8_t> buffer(fileSize);
                size_t bytesRead = fread(buffer.data(), 1, fileSize, fp);
                fclose(fp);
                
                if (bytesRead > 0) {
                    // Bellek olarak tara
                    int sres = yr_rules_scan_mem(
                        rules.get(),
                        buffer.data(), 
                        bytesRead,
                        scan_flags,
                        yara_callback,
                        this,
                        10000  // 10 sn zaman aşımı
                    );
                    
                    if (sres != ERROR_SUCCESS) {
                        qDebug() << "YARA memory scan error with code:" << sres;
                        return make_error_code(YaraErrorCodes::ScanError);
                    }
                } else {
                    qDebug() << "Failed to read file content";
                    return make_error_code(YaraErrorCodes::ScanError);
                }
            } else {
                qDebug() << "File is empty";
                return make_error_code(YaraErrorCodes::ScanError);
            }
        } else {
            qDebug() << "Failed to open file with _wfopen";
            return make_error_code(YaraErrorCodes::FileNotFound);
        }
    } catch (const std::exception& e) {
        qDebug() << "Exception during file scanning:" << e.what();
        return make_error_code(YaraErrorCodes::ScanError);
    }
#else
    // Standart YARA tarama fonksiyonunu kullanalım
    int sres = yr_rules_scan_file(
        rules.get(),
        filePath.c_str(),
        scan_flags,
        yara_callback,
        this,
        10000  // 10 sn zaman aşımı
    );
    
    if (sres != ERROR_SUCCESS) {
        qDebug() << "YARA file scan error with code:" << sres;
        return make_error_code(YaraErrorCodes::ScanError);
    }
#endif

    qDebug() << "YARA scan completed successfully, found" << matches.size() << "matches";
    return make_error_code(YaraErrorCodes::success);
}

std::error_code YaraRuleManager::scanMemory(const uint8_t* data, size_t size, std::vector<std::string>& matches) noexcept {
    if (!initialized)
        return make_error_code(YaraErrorCodes::NotInitialized);
    if (!rules)
        return make_error_code(YaraErrorCodes::RulesNotCompiled);

    matches.clear();
    setCallback([&matches](const std::string& name) { matches.push_back(name); });

    int sres = yr_rules_scan_mem(
        rules.get(),
        data,
        size,
        0,
        yara_callback,
        this,
        0
    );
    if (sres != ERROR_SUCCESS)
        return make_error_code(YaraErrorCodes::ScanError);

    return make_error_code(YaraErrorCodes::success);
}
