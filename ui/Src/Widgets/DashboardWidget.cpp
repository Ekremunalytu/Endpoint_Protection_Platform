#include "Widgets/DashboardWidget.h"
#include "Interfaces/Headers/IDbManager.h"
#include <QSqlQuery>
#include <QSqlError>
#include <QDateTime>
#include <QDebug>
#include <QtCharts/QChartView>
#include <QtCharts/QPieSeries>
#include <QtCharts/QBarSeries>
#include <QtCharts/QBarSet>
#include <QtCharts/QBarCategoryAxis>
#include <QtCharts/QValueAxis>
#include <QGroupBox>

DashboardWidget::DashboardWidget(IDbManager* dbManager, QWidget* parent)
    : QWidget(parent),
      m_dbManager(dbManager)
{
    if (!m_dbManager) {
        qWarning() << "DashboardWidget: DbManager is null, some features may not work";
    }
    
    createLayout();
    
    // Periyodik güncelleme için timer
    m_updateTimer = new QTimer(this);
    connect(m_updateTimer, &QTimer::timeout, this, &DashboardWidget::updateChartsAndStats);
    m_updateTimer->start(60000); // Her 1 dakikada bir güncelle
    
    // İlk çalıştırmada hemen güncelle
    updateChartsAndStats();
}

void DashboardWidget::createLayout()
{
    m_mainLayout = new QGridLayout(this);
    m_mainLayout->setSpacing(20);
    m_mainLayout->setContentsMargins(0, 0, 0, 0);
    
    // Üst bölüm - Başlık ve genel durum
    QVBoxLayout* topLayout = new QVBoxLayout();
    
    // Başlık
    QLabel* titleLabel = new QLabel(tr("Security Dashboard"), this);
    titleLabel->setObjectName("sectionTitleLabel");
    topLayout->addWidget(titleLabel);
    
    // Genel durum paneli
    QGroupBox* statusGroupBox = new QGroupBox(tr("System Status"), this);
    QVBoxLayout* statusLayout = new QVBoxLayout(statusGroupBox);
    
    QLabel* statusLabel = new QLabel(tr("Protection Status: <span style='color:green;font-weight:bold;'>Active</span>"), this);
    statusLayout->addWidget(statusLabel);
    
    QHBoxLayout* lastUpdateLayout = new QHBoxLayout();
    QLabel* lastUpdateLabel = new QLabel(tr("Last Rule Update: %1").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm")), this);
    QPushButton* updateBtn = new QPushButton(tr("Check for Updates"), this);
    
    lastUpdateLayout->addWidget(lastUpdateLabel);
    lastUpdateLayout->addStretch();
    lastUpdateLayout->addWidget(updateBtn);
    
    statusLayout->addLayout(lastUpdateLayout);
    
    topLayout->addWidget(statusGroupBox);
    
    // Üst layout'u ana grid'e ekle
    m_mainLayout->addLayout(topLayout, 0, 0, 1, 2); // 1 satır 2 sütun
    
    // İstatistik kartları
    QGroupBox* statsGroupBox = new QGroupBox(tr("Scan Statistics"), this);
    QHBoxLayout* statsLayout = new QHBoxLayout(statsGroupBox);
    
    // Toplam Tarama
    QVBoxLayout* totalScansLayout = new QVBoxLayout();
    QLabel* totalScansTitle = new QLabel(tr("Total Scans"), this);
    totalScansTitle->setAlignment(Qt::AlignCenter);
    m_totalScansLabel = new QLabel("0", this);
    m_totalScansLabel->setObjectName("statsNumber");
    m_totalScansLabel->setAlignment(Qt::AlignCenter);
    totalScansLayout->addWidget(totalScansTitle);
    totalScansLayout->addWidget(m_totalScansLabel);
    
    // Temiz Dosyalar
    QVBoxLayout* cleanFilesLayout = new QVBoxLayout();
    QLabel* cleanFilesTitle = new QLabel(tr("Clean Files"), this);
    cleanFilesTitle->setAlignment(Qt::AlignCenter);
    m_cleanFilesLabel = new QLabel("0", this);
    m_cleanFilesLabel->setObjectName("statsNumber");
    m_cleanFilesLabel->setAlignment(Qt::AlignCenter);
    cleanFilesLayout->addWidget(cleanFilesTitle);
    cleanFilesLayout->addWidget(m_cleanFilesLabel);
    
    // Tehditler
    QVBoxLayout* threatsLayout = new QVBoxLayout();
    QLabel* threatsTitle = new QLabel(tr("Threats Detected"), this);
    threatsTitle->setAlignment(Qt::AlignCenter);
    m_threatsDetectedLabel = new QLabel("0", this);
    m_threatsDetectedLabel->setObjectName("statsNumber");
    m_threatsDetectedLabel->setAlignment(Qt::AlignCenter);
    threatsLayout->addWidget(threatsTitle);
    threatsLayout->addWidget(m_threatsDetectedLabel);
    
    // Tüm istatistikleri ekle
    statsLayout->addLayout(totalScansLayout);
    statsLayout->addLayout(cleanFilesLayout);
    statsLayout->addLayout(threatsLayout);
    
    // İstatistik kartlarını ana grid'e ekle
    m_mainLayout->addWidget(statsGroupBox, 1, 0, 1, 2);
    
    // Grafik bölümü - Pasta grafik
    m_pieChartView = new QChartView(this);
    m_pieChartView->setRenderHint(QPainter::Antialiasing);
    m_pieChartView->chart()->setTitle(tr("Scan Results Distribution"));
    m_pieChartView->chart()->legend()->setVisible(true);
    m_pieChartView->chart()->legend()->setAlignment(Qt::AlignBottom);
    
    // Grafik bölümü - Çubuk grafik
    m_barChartView = new QChartView(this);
    m_barChartView->setRenderHint(QPainter::Antialiasing);
    m_barChartView->chart()->setTitle(tr("Daily Scan Activity (Last 7 Days)"));
    m_barChartView->chart()->legend()->setVisible(true);
    m_barChartView->chart()->legend()->setAlignment(Qt::AlignBottom);
    
    // Grafikleri ana grid'e ekle
    m_mainLayout->addWidget(m_pieChartView, 2, 0);
    m_mainLayout->addWidget(m_barChartView, 2, 1);
    
    // Son taramalar bölümü
    QGroupBox* recentScansBox = new QGroupBox(tr("Recent Scans"), this);
    QVBoxLayout* recentScansLayout = new QVBoxLayout(recentScansBox);
    
    // Son taramalar için bir liste görünümü oluşturulabilir
    // Şimdilik boş bıraktık, updateRecentScans() metodu ile dolduracağız
    
    // Son taramaları ana grid'e ekle
    m_mainLayout->addWidget(recentScansBox, 3, 0, 1, 2);
    
    setLayout(m_mainLayout);
}

void DashboardWidget::updateStats()
{
    if (!m_dbManager || !m_dbManager->isDatabaseConnected()) {
        qWarning() << "Cannot update stats: database not connected";
        return;
    }
    
    try {
        // Toplam tarama sayısını sorgula
        QSqlQuery totalQuery("SELECT COUNT(*) FROM scan_results", m_dbManager->getDatabase());
        if (totalQuery.next()) {
            m_totalScansLabel->setText(QString::number(totalQuery.value(0).toInt()));
        }
        
        // Temiz dosya sayısını sorgula
        QSqlQuery cleanQuery("SELECT COUNT(*) FROM scan_results WHERE is_clean = 1", m_dbManager->getDatabase());
        if (cleanQuery.next()) {
            m_cleanFilesLabel->setText(QString::number(cleanQuery.value(0).toInt()));
        }
        
        // Tehdit sayısını sorgula
        QSqlQuery threatQuery("SELECT COUNT(*) FROM scan_results WHERE is_clean = 0", m_dbManager->getDatabase());
        if (threatQuery.next()) {
            m_threatsDetectedLabel->setText(QString::number(threatQuery.value(0).toInt()));
        }
    }
    catch (const std::exception& e) {
        qWarning() << "Error updating stats:" << e.what();
    }
}

void DashboardWidget::updateRecentScans()
{
    if (!m_dbManager || !m_dbManager->isDatabaseConnected()) {
        qWarning() << "Cannot update recent scans: database not connected";
        return;
    }
    
    // fetchRecentScans() ile son 5 taramayı çekiyoruz
    QList<QMap<QString, QVariant>> recentScans = fetchRecentScans();
    
    // Şu an için özel bir görsel öğe eklemeyi atladık
    // İleride bu bölümü bir QTableView veya özel bir liste görünümü ile doldurabiliriz
}

void DashboardWidget::updateChartsAndStats()
{
    // İstatistikleri güncelle
    updateStats();
    
    // Son taramaları güncelle
    updateRecentScans();
    
    // Pasta grafiği güncelle
    int cleanFiles = m_cleanFilesLabel->text().toInt();
    int threats = m_threatsDetectedLabel->text().toInt();
    
    QPieSeries* pieSeries = new QPieSeries();
    pieSeries->append(tr("Clean Files"), cleanFiles);
    pieSeries->append(tr("Threats Detected"), threats);
    
    // Temiz dosya dilimini yeşil, tehdit dilimini kırmızı yap
    if (pieSeries->count() > 0) {
        pieSeries->slices().at(0)->setBrush(QColor(0, 150, 0));
    }
    if (pieSeries->count() > 1) {
        pieSeries->slices().at(1)->setBrush(QColor(200, 0, 0));
    }
    
    m_pieChartView->chart()->removeAllSeries();
    m_pieChartView->chart()->addSeries(pieSeries);
    
    // Çubuk grafik için son 7 günün verilerini çek
    fetchScanStatistics();
}

void DashboardWidget::fetchScanStatistics()
{
    if (!m_dbManager || !m_dbManager->isDatabaseConnected()) {
        qWarning() << "Cannot fetch scan statistics: database not connected";
        return;
    }
    
    try {
        // SQL sorgusu - son 7 günde, gün başına tarama sayısı
        QString query = R"(
            SELECT 
                date(timestamp) as scan_date,
                COUNT(*) as scan_count
            FROM 
                scan_results
            WHERE 
                timestamp >= date('now', '-7 days')
            GROUP BY 
                date(timestamp)
            ORDER BY 
                scan_date ASC
        )";
        
        QSqlQuery sqlQuery(query, m_dbManager->getDatabase());
        
        // Günlük tarama verilerini topla
        QStringList categories;
        QBarSet* scanSet = new QBarSet(tr("Scans"));
        
        // Son 7 günü hazırla
        QMap<QString, int> dailyScans;
        QDate currentDate = QDate::currentDate();
        for (int i = 6; i >= 0; i--) {
            QDate date = currentDate.addDays(-i);
            dailyScans[date.toString("yyyy-MM-dd")] = 0;
            categories << date.toString("MM-dd");
        }
        
        // Veritabanındaki verileri ekle
        while (sqlQuery.next()) {
            QString scanDate = sqlQuery.value("scan_date").toString();
            int scanCount = sqlQuery.value("scan_count").toInt();
            
            if (dailyScans.contains(scanDate)) {
                dailyScans[scanDate] = scanCount;
            }
        }
        
        // Veri setine değerleri ekle
        for (int i = 6; i >= 0; i--) {
            QDate date = currentDate.addDays(-i);
            QString dateKey = date.toString("yyyy-MM-dd");
            *scanSet << dailyScans[dateKey];
        }
        
        // Bar series oluştur
        QBarSeries* barSeries = new QBarSeries();
        barSeries->append(scanSet);
        
        // Çubuk grafik eksenleri
        QBarCategoryAxis* axisX = new QBarCategoryAxis();
        axisX->append(categories);
        
        QValueAxis* axisY = new QValueAxis();
        axisY->setRange(0, 10); // Minimum 0, maksimum 10 göster (veya dinamik olarak ayarlanabilir)
        axisY->setTickCount(6);
        axisY->setLabelFormat("%d");
        
        // Grafiği temizle ve yeni seriyi ekle
        m_barChartView->chart()->removeAllSeries();
        m_barChartView->chart()->addSeries(barSeries);
        m_barChartView->chart()->setAxisX(axisX, barSeries);
        m_barChartView->chart()->setAxisY(axisY, barSeries);
    }
    catch (const std::exception& e) {
        qWarning() << "Error fetching scan statistics:" << e.what();
    }
}

QList<QMap<QString, QVariant>> DashboardWidget::fetchRecentScans()
{
    QList<QMap<QString, QVariant>> result;
    
    if (!m_dbManager || !m_dbManager->isDatabaseConnected()) {
        return result;
    }
    
    try {
        // SQL sorgusu - son 5 tarama
        QString query = R"(
            SELECT 
                id,
                scan_type,
                file_name,
                is_clean,
                datetime(timestamp, 'localtime') as formatted_time
            FROM 
                scan_results
            ORDER BY 
                timestamp DESC
            LIMIT 5
        )";
        
        QSqlQuery sqlQuery(query, m_dbManager->getDatabase());
        
        // Sorgu sonuçlarını işle
        while (sqlQuery.next()) {
            QMap<QString, QVariant> scanInfo;
            scanInfo["id"] = sqlQuery.value("id");
            scanInfo["scan_type"] = sqlQuery.value("scan_type");
            scanInfo["file_name"] = sqlQuery.value("file_name");
            scanInfo["is_clean"] = sqlQuery.value("is_clean");
            scanInfo["time"] = sqlQuery.value("formatted_time");
            
            result.append(scanInfo);
        }
    }
    catch (const std::exception& e) {
        qWarning() << "Error fetching recent scans:" << e.what();
    }
    
    return result;
}