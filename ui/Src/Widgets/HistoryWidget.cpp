#include "Widgets/HistoryWidget.h"
#include "Interfaces/Headers/IDbManager.h"
#include <QSqlQuery>
#include <QSqlError>
#include <QDateTime>
#include <QMessageBox>
#include <QFileDialog>
#include <QStandardPaths>
#include <QTextStream>
#include <QDebug>
#include <QTextEdit>
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

HistoryWidget::HistoryWidget(IDbManager* dbManager, QWidget* parent)
    : QWidget(parent),
      m_dbManager(dbManager)
{
    if (!m_dbManager) {
        throw std::runtime_error("HistoryWidget: DbManager cannot be null");
    }
    
    createLayout();
    setupConnections();
    refreshHistory(); // İlk çağrı ile tabloyu doldur
}

void HistoryWidget::createLayout()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    
    // Başlık
    QLabel* titleLabel = new QLabel(tr("Scan History"), this);
    titleLabel->setObjectName("sectionTitleLabel");
    mainLayout->addWidget(titleLabel);
    
    // Filtre kontrollerini içerecek yatay düzen
    QHBoxLayout* filterLayout = new QHBoxLayout();
    
    // Filtre seçenekleri
    QLabel* typeLabel = new QLabel(tr("Filter by:"), this);
    m_filterType = new QComboBox(this);
    m_filterType->addItem(tr("All"), "");
    m_filterType->addItem(tr("File Name"), "file_name");
    m_filterType->addItem(tr("Scan Type"), "scan_type");
    m_filterType->addItem(tr("Status"), "is_clean");
    
    m_filterText = new QLineEdit(this);
    m_filterText->setPlaceholderText(tr("Filter text..."));
    
    filterLayout->addWidget(typeLabel);
    filterLayout->addWidget(m_filterType);
    filterLayout->addWidget(m_filterText);
    
    // Tarih filtreleri
    QLabel* dateLabel = new QLabel(tr("Date Range:"), this);
    m_fromDate = new QDateEdit(QDate::currentDate().addDays(-30), this);
    m_toDate = new QDateEdit(QDate::currentDate(), this);
    m_fromDate->setCalendarPopup(true);
    m_toDate->setCalendarPopup(true);
    
    filterLayout->addWidget(dateLabel);
    filterLayout->addWidget(m_fromDate);
    filterLayout->addWidget(m_toDate);
    
    // Filtre ve yenileme butonları
    m_filterButton = new QPushButton(tr("Apply Filter"), this);
    m_refreshButton = new QPushButton(tr("Refresh"), this);
    
    filterLayout->addWidget(m_filterButton);
    filterLayout->addWidget(m_refreshButton);
    filterLayout->addStretch();
    
    mainLayout->addLayout(filterLayout);
    
    // Tablo görünümü
    m_historyTable = new QTableView(this);
    m_historyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_historyTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_historyTable->setAlternatingRowColors(true);
    m_historyTable->setSortingEnabled(true);
    m_historyTable->horizontalHeader()->setStretchLastSection(true);
    m_historyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    
    m_historyModel = new QSqlQueryModel(this);
    m_historyTable->setModel(m_historyModel);
    
    mainLayout->addWidget(m_historyTable, 1); // 1 = stretch factor
    
    // Dışa aktarma butonu için alt düzen
    QHBoxLayout* bottomLayout = new QHBoxLayout();
    m_exportButton = new QPushButton(tr("Export Results"), this);
    bottomLayout->addStretch();
    bottomLayout->addWidget(m_exportButton);
    
    mainLayout->addLayout(bottomLayout);
    
    setLayout(mainLayout);
}

void HistoryWidget::setupConnections()
{
    connect(m_filterButton, &QPushButton::clicked, this, &HistoryWidget::filterResults);
    connect(m_refreshButton, &QPushButton::clicked, this, &HistoryWidget::refreshHistory);
    connect(m_historyTable, &QTableView::doubleClicked, this, &HistoryWidget::showDetails);
    connect(m_exportButton, &QPushButton::clicked, this, [this]() {
        // Dışa aktarma işlemi
        QString fileName = QFileDialog::getSaveFileName(this,
                                                      tr("Export Scan History"),
                                                      QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/scan_history.csv",
                                                      tr("CSV Files (*.csv);;All Files (*)"));
        
        if (fileName.isEmpty()) {
            return;
        }
        
        QFile file(fileName);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::critical(this, tr("Export Error"), tr("Could not open file for writing: %1").arg(file.errorString()));
            return;
        }
        
        QTextStream out(&file);
        
        // Header satırı
        QStringList headers;
        for (int i = 0; i < m_historyModel->columnCount(); ++i) {
            headers << m_historyModel->headerData(i, Qt::Horizontal).toString();
        }
        out << headers.join(",") << "\n";
        
        // Veri satırları
        for (int row = 0; row < m_historyModel->rowCount(); ++row) {
            QStringList rowData;
            for (int col = 0; col < m_historyModel->columnCount(); ++col) {
                QString data = m_historyModel->data(m_historyModel->index(row, col)).toString();
                // CSV formatı için verinin düzenlenmesi
                data.replace("\"", "\"\""); // Tırnak işaretlerini escape et
                if (data.contains(",") || data.contains("\"") || data.contains("\n")) {
                    data = "\"" + data + "\"";
                }
                rowData << data;
            }
            out << rowData.join(",") << "\n";
        }
        
        file.close();
        QMessageBox::information(this, tr("Export Successful"), tr("Scan history exported successfully!"));
    });
}

void HistoryWidget::refreshHistory()
{
    if (!m_dbManager || !m_dbManager->isDatabaseConnected()) {
        QMessageBox::warning(this, tr("Database Error"), tr("Database connection is not available."));
        return;
    }
    
    try {
        // Basit bir sorgu ile tüm tarama geçmişini çek
        QString query = R"(
            SELECT 
                id, 
                scan_type AS "Scan Type", 
                file_name AS "File Name", 
                CASE WHEN is_clean = 1 THEN 'Clean' ELSE 'Threat Detected' END AS "Status", 
                datetime(timestamp, 'localtime') AS "Timestamp"
            FROM 
                scan_results 
            ORDER BY 
                timestamp DESC
        )";
        
        m_historyModel->setQuery(QSqlQuery(query, m_dbManager->getDatabase()));
        
        if (m_historyModel->lastError().isValid()) {
            QMessageBox::critical(this, 
                                 tr("Database Error"),
                                 tr("Failed to fetch scan history: %1").arg(m_historyModel->lastError().text()));
        }
        
        // İlk ID sütununu gizle
        m_historyTable->setColumnHidden(0, true);
        
        // Sütun genişliklerini ayarla
        m_historyTable->setColumnWidth(1, 120);  // Scan Type
        m_historyTable->setColumnWidth(2, 300);  // File Name
        m_historyTable->setColumnWidth(3, 120);  // Status
        // Son sütun (Timestamp) zaten stretch last section özelliğiyle otomatik genişler
    }
    catch (const std::exception& e) {
        QMessageBox::critical(this, 
                             tr("Error"),
                             tr("Failed to load scan history: %1").arg(e.what()));
    }
}

void HistoryWidget::filterResults()
{
    QString filterType = m_filterType->currentData().toString();
    QString filterText = m_filterText->text().trimmed();
    QDate fromDate = m_fromDate->date();
    QDate toDate = m_toDate->date();
    
    // Tarih kontrolü
    if (fromDate > toDate) {
        QMessageBox::warning(this,
                            tr("Invalid Date Range"),
                            tr("Start date cannot be later than end date."));
        return;
    }
    
    try {
        // Sorgu oluştur
        QString query = R"(
            SELECT 
                id, 
                scan_type AS "Scan Type", 
                file_name AS "File Name", 
                CASE WHEN is_clean = 1 THEN 'Clean' ELSE 'Threat Detected' END AS "Status", 
                datetime(timestamp, 'localtime') AS "Timestamp"
            FROM 
                scan_results 
            WHERE 
                date(timestamp) BETWEEN date(?) AND date(?)
        )";
        
        // Eğer filtre tipi ve metni belirtilmişse ek koşul ekle
        if (!filterType.isEmpty() && !filterText.isEmpty()) {
            if (filterType == "is_clean") {
                // Status filtresi özel durum (boolean değer)
                bool isClean = (filterText.toLower() == "clean" || filterText == "1" || filterText.toLower() == "true");
                query += QString(" AND %1 = %2").arg(filterType).arg(isClean ? "1" : "0");
            } else {
                query += QString(" AND %1 LIKE '%%2%'").arg(filterType).arg(filterText);
            }
        }
        
        query += " ORDER BY timestamp DESC";
        
        QSqlQuery sqlQuery(m_dbManager->getDatabase());
        sqlQuery.prepare(query);
        sqlQuery.addBindValue(fromDate.toString("yyyy-MM-dd"));
        sqlQuery.addBindValue(toDate.toString("yyyy-MM-dd"));
        
        m_historyModel->setQuery(sqlQuery);
        
        if (m_historyModel->lastError().isValid()) {
            QMessageBox::critical(this, 
                                 tr("Database Error"),
                                 tr("Failed to filter scan history: %1").arg(m_historyModel->lastError().text()));
        }
        
        // İlk ID sütununu gizle
        m_historyTable->setColumnHidden(0, true);
    }
    catch (const std::exception& e) {
        QMessageBox::critical(this, 
                             tr("Error"),
                             tr("Failed to filter scan history: %1").arg(e.what()));
    }
}

void HistoryWidget::showDetails(const QModelIndex& index)
{
    if (!index.isValid()) {
        return;
    }
    
    // Seçilen satırın ID'sini al
    int row = index.row();
    QModelIndex idIndex = m_historyModel->index(row, 0);
    int scanId = m_historyModel->data(idIndex).toInt();
    
    try {
        // Seçilen tarama kaydının detaylarını al
        QString query = "SELECT * FROM scan_results WHERE id = ?";
        QSqlQuery sqlQuery(m_dbManager->getDatabase());
        sqlQuery.prepare(query);
        sqlQuery.addBindValue(scanId);
        
        if (!sqlQuery.exec() || !sqlQuery.next()) {
            QMessageBox::critical(this, 
                                 tr("Database Error"),
                                 tr("Failed to fetch scan details: %1").arg(sqlQuery.lastError().text()));
            return;
        }
        
        // Detayları içeren bir iletişim kutusu oluştur
        QDialog dialog(this);
        dialog.setWindowTitle(tr("Scan Details"));
        dialog.setMinimumSize(600, 400);
        
        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        
        // Temel bilgiler
        QLabel* scanTypeLabel = new QLabel(tr("<b>Scan Type:</b> %1").arg(sqlQuery.value("scan_type").toString()));
        QLabel* fileNameLabel = new QLabel(tr("<b>File Name:</b> %1").arg(sqlQuery.value("file_name").toString()));
        QLabel* filePathLabel = new QLabel(tr("<b>File Path:</b> %1").arg(sqlQuery.value("file_path").toString()));
        QLabel* statusLabel = new QLabel(tr("<b>Status:</b> %1").arg(sqlQuery.value("is_clean").toBool() ? "Clean" : "Threat Detected"));
        QLabel* timestampLabel = new QLabel(tr("<b>Time:</b> %1").arg(sqlQuery.value("timestamp").toDateTime().toString("yyyy-MM-dd hh:mm:ss")));
        
        layout->addWidget(scanTypeLabel);
        layout->addWidget(fileNameLabel);
        layout->addWidget(filePathLabel);
        layout->addWidget(statusLabel);
        layout->addWidget(timestampLabel);
        
        // Sonuç detayları
        QLabel* resultLabel = new QLabel(tr("<b>Scan Results:</b>"));
        QTextEdit* resultText = new QTextEdit();
        resultText->setReadOnly(true);
        resultText->setHtml(sqlQuery.value("result").toString());
        
        layout->addWidget(resultLabel);
        layout->addWidget(resultText, 1); // Stretch factor 1
        
        // Kapat butonu
        QPushButton* closeButton = new QPushButton(tr("Close"));
        connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        
        QHBoxLayout* buttonLayout = new QHBoxLayout();
        buttonLayout->addStretch();
        buttonLayout->addWidget(closeButton);
        layout->addLayout(buttonLayout);
        
        dialog.setLayout(layout);
        dialog.exec();
    }
    catch (const std::exception& e) {
        QMessageBox::critical(this, 
                             tr("Error"),
                             tr("Failed to show scan details: %1").arg(e.what()));
    }
}