#ifndef APIKEYDIALOG_H
#define APIKEYDIALOG_H

#include <QDialog>
#include <QLineEdit>

/**
 * @brief API anahtarı ayarlamak için diyalog sınıfı
 * VirusTotal API anahtarını ayarlamak için kullanılır
 */
class ApiKeyDialog : public QDialog {
    Q_OBJECT
private:
    QLineEdit* apiKeyLineEdit;

public:
    /**
     * @brief Yapıcı metod
     * @param parent Üst widget
     */
    explicit ApiKeyDialog(QWidget *parent = nullptr);
    
    /**
     * @brief API anahtarını döndürür
     * @return Kullanıcının girdiği API anahtarı
     */
    QString getApiKey() const { return apiKeyLineEdit->text(); }
};

#endif // APIKEYDIALOG_H