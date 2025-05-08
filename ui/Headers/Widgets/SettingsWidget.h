#ifndef SETTINGSWIDGET_H
#define SETTINGSWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QGroupBox>
#include <QComboBox>
#include <QTabWidget>
#include <QFileDialog>
#include <QSpinBox>
#include <QSettings>
#include <QMessageBox>

/**
 * @brief Ayarlar sayfası widget'ı
 * Kullanıcının uygulama ayarlarını yapılandırmasını sağlar
 */
class SettingsWidget : public QWidget
{
    Q_OBJECT

public:
    /**
     * @brief Yapıcı metod
     * @param settings QSettings nesnesi
     * @param parent Üst widget
     */
    explicit SettingsWidget(QSettings* settings, QWidget* parent = nullptr);
    
    /**
     * @brief Destructor
     */
    ~SettingsWidget() override = default;

private slots:
    /**
     * @brief Ayarları kaydet
     */
    void saveSettings();
    
    /**
     * @brief Ayarları varsayılana sıfırla
     */
    void resetToDefaults();
    
    /**
     * @brief Yara kuralları dizinini seç
     */
    void selectYaraRulesDir();
    
    /**
     * @brief Tarama çıktısı dizinini seç
     */
    void selectScanOutputDir();

private:
    /**
     * @brief UI bileşenlerini oluşturur
     */
    void createLayout();
    
    /**
     * @brief Mevcut ayarları UI'a yükler
     */
    void loadSettings();
    
    /**
     * @brief Varsayılan ayarları yükler
     */
    void loadDefaults();
    
    /**
     * @brief UI değişikliklerini kaydeder
     * @param showConfirmation Onay mesajı göster
     */
    void applySettings(bool showConfirmation);
    
    // QSettings
    QSettings* m_settings;
    
    // UI Bileşenleri - Genel
    QTabWidget* m_tabWidget;
    
    // Genel Ayarlar Tab
    QCheckBox* m_startOnBootCheckbox;
    QCheckBox* m_minimizeToTrayCheckbox;
    QCheckBox* m_confirmExitCheckbox;
    
    // Tarama Ayarları Tab
    QLineEdit* m_yaraRulesDir;
    QLineEdit* m_scanOutputDir;
    QPushButton* m_yaraRulesDirButton;
    QPushButton* m_scanOutputDirButton;
    QSpinBox* m_scanTimeoutSpinBox;
    QCheckBox* m_autoScanDownloadsCheckbox;
    
    // VirusTotal Ayarları Tab
    QLineEdit* m_virusTotalApiKey;
    QCheckBox* m_submitHashesOnlyCheckbox;
    QSpinBox* m_apiRequestDelaySpinBox;
    
    // Butonlar
    QPushButton* m_applyButton;
    QPushButton* m_resetButton;
};

#endif // SETTINGSWIDGET_H