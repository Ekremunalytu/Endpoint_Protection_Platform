#ifndef HISTORYDIALOG_H
#define HISTORYDIALOG_H

#include <QDialog>
#include <QTabWidget>
#include <QTableWidget>
#include <QPushButton>
#include <memory>
#include <vector>

/**
 * @brief Geçmiş tarama işlemlerini gösteren diyalog
 * Offline tarama, VirusTotal sonuçları, CDR ve Sandbox işlem geçmişini gösterir
 */
class HistoryDialog : public QDialog {
    Q_OBJECT
private:
    QTabWidget* m_tabWidget;
    QTableWidget* m_scanHistoryTable;
    QTableWidget* m_vtHistoryTable;
    QTableWidget* m_cdrHistoryTable;
    QTableWidget* m_sandboxHistoryTable;
    QPushButton* m_clearHistoryButton;
    QPushButton* m_exportHistoryButton;
    QPushButton* m_closeButton;

    // Thread-safe operations için mutex
    std::unique_ptr<std::mutex> m_historyMutex;

public:
    /**
     * @brief Yapıcı metod
     * @param parent Üst widget
     */
    explicit HistoryDialog(QWidget* parent = nullptr);
    
    /**
     * @brief Destructor
     */
    ~HistoryDialog() override = default;

private slots:
    /**
     * @brief Seçili geçmiş kategorisini temizler
     */
    void clearSelectedHistory();
    
    /**
     * @brief Geçmiş verilerini dışa aktarır
     */
    void exportHistory();

private:
    /**
     * @brief UI bileşenlerini oluşturur
     */
    void createUI();
    
    /**
     * @brief Geçmiş verilerini yükler
     */
    void loadHistory();
    
    /**
     * @brief Bağlantıları ayarlar
     */
    void setupConnections();
    
    /**
     * @brief Tablo başlıklarını ayarlar
     * @param table Ayarlanacak tablo
     * @param headers Tablo başlıkları
     */
    void setupTableHeaders(QTableWidget* table, const QStringList& headers);
    
    /**
     * @brief Örnek veri ekleme yardımcı fonksiyonu (geliştirme amaçlı)
     * @param table Veri eklenecek tablo
     * @param count Eklenecek örnek veri sayısı
     */
    void addExampleData(QTableWidget* table, int count);
};

#endif // HISTORYDIALOG_H