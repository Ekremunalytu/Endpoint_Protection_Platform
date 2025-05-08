#ifndef DOCKERIMAGESELECTIONDIALOG_H
#define DOCKERIMAGESELECTIONDIALOG_H

#include <QDialog>
#include <QComboBox>
#include <QStringList>

/**
 * @brief Docker imajı seçimi için diyalog sınıfı
 * CDR ve Sandbox servisleri için Docker imajı seçiminde kullanılır
 */
class DockerImageSelectionDialog : public QDialog {
    Q_OBJECT
private:
    QComboBox* imageComboBox;

public:
    /**
     * @brief Yapıcı metod
     * @param availableImages Kullanılabilir Docker imajları listesi
     * @param currentImage Şu anki seçili imaj
     * @param serviceType Servis tipi ("CDR" veya "Sandbox")
     * @param parent Üst widget
     */
    DockerImageSelectionDialog(const QStringList& availableImages, 
                              const QString& currentImage, 
                              const QString& serviceType, 
                              QWidget* parent = nullptr);
    
    /**
     * @brief Seçili Docker imajını döndürür
     * @return Kullanıcının seçtiği Docker imajı adı
     */
    QString getSelectedImage() const;
};

#endif // DOCKERIMAGESELECTIONDIALOG_H