#ifndef HISTORYWIDGET_H
#define HISTORYWIDGET_H

#include <QWidget>
#include <QTableView>
#include <QSqlQueryModel>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QDateEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>

class IDbManager;

/**
 * @brief Tarama geçmişini gösteren ve yöneten widget
 */
class HistoryWidget : public QWidget
{
    Q_OBJECT
    
public:
    /**
     * @brief Yapıcı metod
     * @param dbManager Veritabanı yöneticisi
     * @param parent Üst widget
     */
    explicit HistoryWidget(IDbManager* dbManager, QWidget* parent = nullptr);
    
    /**
     * @brief Destructor
     */
    ~HistoryWidget() override = default;
    
private slots:
    /**
     * @brief Geçmiş tarama kayıtlarını yeniler
     */
    void refreshHistory();
    
    /**
     * @brief Filtreleme kriterlerine göre tarama kayıtlarını filtreler
     */
    void filterResults();
    
    /**
     * @brief Seçilen satırın detaylarını gösterir
     * @param index Seçilen satırın indeksi
     */
    void showDetails(const QModelIndex& index);
    
private:
    /**
     * @brief UI bileşenlerini oluşturur
     */
    void createLayout();
    
    /**
     * @brief Sinyal ve slot bağlantılarını kurar
     */
    void setupConnections();
    
    // Veritabanı yöneticisi
    IDbManager* m_dbManager;
    
    // UI bileşenleri
    QTableView* m_historyTable;
    QSqlQueryModel* m_historyModel;
    QComboBox* m_filterType;
    QLineEdit* m_filterText;
    QDateEdit* m_fromDate;
    QDateEdit* m_toDate;
    QPushButton* m_filterButton;
    QPushButton* m_refreshButton;
    QPushButton* m_exportButton;
};

#endif // HISTORYWIDGET_H