#ifndef DASHBOARDWIDGET_H
#define DASHBOARDWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QChartView>
#include <QPieSeries>
#include <QBarSeries>
#include <QGridLayout>
#include <QTimer>

class IDbManager;

/**
 * @brief Ana ekran widget'ı
 * Sistemin genel durumunu ve istatistikleri gösterir
 */
class DashboardWidget : public QWidget
{
    Q_OBJECT

public:
    /**
     * @brief Yapıcı metod
     * @param dbManager Veritabanı yöneticisi
     * @param parent Üst widget
     */
    explicit DashboardWidget(IDbManager* dbManager, QWidget* parent = nullptr);

    /**
     * @brief Destructor
     */
    ~DashboardWidget() override = default;

public slots:
    /**
     * @brief İstatistikleri günceller
     */
    void updateStats();

    /**
     * @brief Son tarama sonuçlarını günceller
     */
    void updateRecentScans();

private:
    /**
     * @brief UI bileşenlerini oluşturur
     */
    void createLayout();
    
    /**
     * @brief Veritabanı bağlantısı gerektiren grafik ve istatistikleri günceller
     */
    void updateChartsAndStats();
    
    /**
     * @brief Son 30 gündeki tarama istatistiklerini çeker
     */
    void fetchScanStatistics();
    
    /**
     * @brief Kullanılan veritabanından son 5 taramayı çeker
     * @return Son 5 tarama kaydı
     */
    QList<QMap<QString, QVariant>> fetchRecentScans();

    // Veritabanı yöneticisi
    IDbManager* m_dbManager;
    
    // Ana bileşenler
    QGridLayout* m_mainLayout;
    
    // İstatistik bileşenleri
    QLabel* m_totalScansLabel;
    QLabel* m_cleanFilesLabel;
    QLabel* m_threatsDetectedLabel;
    
    // Grafik bileşenleri
    QChartView* m_pieChartView;
    QChartView* m_barChartView;
    
    // Zamanlayıcı - periyodik güncelleme için
    QTimer* m_updateTimer;
};

#endif // DASHBOARDWIDGET_H