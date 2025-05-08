#include "../../Headers/Dialogs/HistoryDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QFileDialog>
#include <QDateTime>
#include <QFile>
#include <QTextStream>
#include <QLabel>
#include <QRandomGenerator>
#include <mutex>

HistoryDialog::HistoryDialog(QWidget* parent)
    : QDialog(parent),
      m_tabWidget(nullptr),
      m_scanHistoryTable(nullptr),
      m_vtHistoryTable(nullptr),
      m_cdrHistoryTable(nullptr),
      m_sandboxHistoryTable(nullptr),
      m_clearHistoryButton(nullptr),
      m_exportHistoryButton(nullptr),
      m_closeButton(nullptr),
      m_historyMutex(std::make_unique<std::mutex>())
{
    setWindowTitle(tr("Scan History"));
    setMinimumSize(900, 700);
    
    createUI();
    setupConnections();
    loadHistory();
}

void HistoryDialog::createUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(20);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    // Başlık
    QLabel* titleLabel = new QLabel(tr("Scan History"), this);
    titleLabel->setObjectName("dialogTitleLabel");
    mainLayout->addWidget(titleLabel);

    // Tab widget
    m_tabWidget = new QTabWidget(this);
    m_tabWidget->setObjectName("historyTabWidget");

    // Offline scan history tab
    m_scanHistoryTable = new QTableWidget(m_tabWidget);
    setupTableHeaders(m_scanHistoryTable, QStringList() 
        << tr("Date & Time") 
        << tr("File") 
        << tr("Size (KB)") 
        << tr("Detected Threats") 
        << tr("Result"));
    
    m_tabWidget->addTab(m_scanHistoryTable, tr("Offline Scans"));

    // VirusTotal history tab
    m_vtHistoryTable = new QTableWidget(m_tabWidget);
    setupTableHeaders(m_vtHistoryTable, QStringList() 
        << tr("Date & Time") 
        << tr("File") 
        << tr("Size (KB)") 
        << tr("Detection Rate") 
        << tr("Analysis ID"));
    
    m_tabWidget->addTab(m_vtHistoryTable, tr("VirusTotal Scans"));

    // CDR history tab
    m_cdrHistoryTable = new QTableWidget(m_tabWidget);
    setupTableHeaders(m_cdrHistoryTable, QStringList() 
        << tr("Date & Time") 
        << tr("Original File") 
        << tr("Sanitized File") 
        << tr("Status") 
        << tr("Processing Time (s)"));
    
    m_tabWidget->addTab(m_cdrHistoryTable, tr("CDR Operations"));

    // Sandbox history tab
    m_sandboxHistoryTable = new QTableWidget(m_tabWidget);
    setupTableHeaders(m_sandboxHistoryTable, QStringList() 
        << tr("Date & Time") 
        << tr("File") 
        << tr("Risk Score") 
        << tr("Status") 
        << tr("Run Duration (s)"));
    
    m_tabWidget->addTab(m_sandboxHistoryTable, tr("Sandbox Analysis"));

    // Add tab widget to main layout
    mainLayout->addWidget(m_tabWidget, 1);

    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    
    m_clearHistoryButton = new QPushButton(tr("Clear Selected History"), this);
    m_exportHistoryButton = new QPushButton(tr("Export to CSV"), this);
    m_closeButton = new QPushButton(tr("Close"), this);
    
    buttonLayout->addWidget(m_clearHistoryButton);
    buttonLayout->addWidget(m_exportHistoryButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(m_closeButton);
    
    mainLayout->addLayout(buttonLayout);
}

void HistoryDialog::setupTableHeaders(QTableWidget* table, const QStringList& headers)
{
    if (!table) return;
    
    table->setColumnCount(headers.size());
    table->setHorizontalHeaderLabels(headers);
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table->setEditTriggers(QTableWidget::NoEditTriggers);
    table->setSelectionBehavior(QTableWidget::SelectRows);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->setVisible(false);
}

void HistoryDialog::setupConnections()
{
    // Buton bağlantıları
    connect(m_clearHistoryButton, &QPushButton::clicked, this, &HistoryDialog::clearSelectedHistory);
    connect(m_exportHistoryButton, &QPushButton::clicked, this, &HistoryDialog::exportHistory);
    connect(m_closeButton, &QPushButton::clicked, this, &QDialog::accept);
}

void HistoryDialog::loadHistory()
{
    std::lock_guard<std::mutex> lock(*m_historyMutex);
    
    try {
        // Not: Gerçek uygulamada bu veriler bir veritabanından yüklenecektir
        // Örnek olarak bazı sahte veriler ekliyoruz
        
        // Offline scan geçmişi örneği
        m_scanHistoryTable->setRowCount(0);
        
        // Örnek veriler ekle
        addExampleData(m_scanHistoryTable, 5);
        
        // VirusTotal geçmişi örneği
        m_vtHistoryTable->setRowCount(0);
        addExampleData(m_vtHistoryTable, 3);
        
        // CDR geçmişi örneği
        m_cdrHistoryTable->setRowCount(0);
        addExampleData(m_cdrHistoryTable, 4);
        
        // Sandbox geçmişi örneği
        m_sandboxHistoryTable->setRowCount(0);
        addExampleData(m_sandboxHistoryTable, 2);
        
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Error"), 
                           tr("An error occurred while loading history: %1").arg(e.what()));
    } catch (...) {
        QMessageBox::warning(this, tr("Error"), 
                           tr("An unknown error occurred while loading history."));
    }
}

void HistoryDialog::clearSelectedHistory()
{
    int currentTabIndex = m_tabWidget->currentIndex();
    QTableWidget* currentTable = nullptr;
    QString historyName;
    
    // Mevcut aktif tabloya bağlı olarak işlem yap
    switch (currentTabIndex) {
        case 0:
            currentTable = m_scanHistoryTable;
            historyName = tr("Offline Scan");
            break;
        case 1:
            currentTable = m_vtHistoryTable;
            historyName = tr("VirusTotal");
            break;
        case 2:
            currentTable = m_cdrHistoryTable;
            historyName = tr("CDR");
            break;
        case 3:
            currentTable = m_sandboxHistoryTable;
            historyName = tr("Sandbox");
            break;
        default:
            return;
    }
    
    // Onaylama diyaloğu göster
    if (QMessageBox::question(this, tr("Confirm Clear History"),
                            tr("Are you sure you want to clear the %1 history?").arg(historyName),
                            QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
        if (currentTable) {
            std::lock_guard<std::mutex> lock(*m_historyMutex);
            currentTable->setRowCount(0);
            
            // Not: Gerçek uygulamada veritabanından silme işlemi yapılacaktır
            
            QMessageBox::information(this, tr("History Cleared"),
                                   tr("%1 history has been cleared.").arg(historyName));
        }
    }
}

void HistoryDialog::exportHistory()
{
    int currentTabIndex = m_tabWidget->currentIndex();
    QTableWidget* currentTable = nullptr;
    QString historyName;
    
    switch (currentTabIndex) {
        case 0:
            currentTable = m_scanHistoryTable;
            historyName = tr("offline_scans");
            break;
        case 1:
            currentTable = m_vtHistoryTable;
            historyName = tr("virustotal_scans");
            break;
        case 2:
            currentTable = m_cdrHistoryTable;
            historyName = tr("cdr_operations");
            break;
        case 3:
            currentTable = m_sandboxHistoryTable;
            historyName = tr("sandbox_analysis");
            break;
        default:
            return;
    }
    
    if (!currentTable || currentTable->rowCount() == 0) {
        QMessageBox::warning(this, tr("Export Error"),
                           tr("There is no data to export."));
        return;
    }
    
    QString fileName = QFileDialog::getSaveFileName(this,
                                                  tr("Save History Data"),
                                                  QDir::homePath() + "/" + historyName + ".csv",
                                                  tr("CSV Files (*.csv);;All Files (*)"));
    
    if (fileName.isEmpty())
        return;
    
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("File Error"),
                           tr("Cannot open file for writing: %1").arg(file.errorString()));
        return;
    }
    
    try {
        std::lock_guard<std::mutex> lock(*m_historyMutex);
        QTextStream out(&file);
        
        // Başlıkları CSV'ye yaz
        for (int col = 0; col < currentTable->columnCount(); ++col) {
            out << "\"" << currentTable->horizontalHeaderItem(col)->text() << "\"";
            if (col < currentTable->columnCount() - 1)
                out << ",";
        }
        out << "\n";
        
        // Verileri CSV'ye yaz
        for (int row = 0; row < currentTable->rowCount(); ++row) {
            for (int col = 0; col < currentTable->columnCount(); ++col) {
                QTableWidgetItem* item = currentTable->item(row, col);
                if (item) {
                    QString text = item->text();
                    // CSV için metni düzenle (örn. çift tırnak karakterleri)
                    text.replace("\"", "\"\""); // CSV formatında çift tırnak, iki çift tırnak olarak kaçırılır
                    out << "\"" << text << "\"";
                } else {
                    out << "\"\"";
                }
                
                if (col < currentTable->columnCount() - 1)
                    out << ",";
            }
            out << "\n";
        }
        
        file.close();
        QMessageBox::information(this, tr("Export Successful"),
                               tr("History data has been exported to %1").arg(fileName));
        
    } catch (const std::exception& e) {
        file.close();
        QMessageBox::warning(this, tr("Export Error"),
                           tr("An error occurred while exporting data: %1").arg(e.what()));
    } catch (...) {
        file.close();
        QMessageBox::warning(this, tr("Export Error"),
                           tr("An unknown error occurred while exporting data."));
    }
}

// Geliştirme sırasında örnek veri ekleme yardımcı metodu
void HistoryDialog::addExampleData(QTableWidget* table, int count)
{
    if (!table) return;
    
    // Farklı tablolar için örnek veri türleri
    QStringList fileTypes;
    QStringList statusValues;
    bool isVirusTotalTable = (table == m_vtHistoryTable);
    bool isCdrTable = (table == m_cdrHistoryTable);
    bool isSandboxTable = (table == m_sandboxHistoryTable);
    
    if (isVirusTotalTable) {
        fileTypes = QStringList() << "document.pdf" << "setup.exe" << "archive.zip" << "image.jpg";
    } else if (isCdrTable) {
        fileTypes = QStringList() << "report.docx" << "presentation.pptx" << "spreadsheet.xlsx" << "document.pdf";
    } else if (isSandboxTable) {
        fileTypes = QStringList() << "unknown.exe" << "installer.msi" << "script.js" << "macro.vbs";
    } else {
        fileTypes = QStringList() << "file.exe" << "document.docx" << "image.png" << "archive.rar";
    }
    
    if (isCdrTable) {
        statusValues = QStringList() << "Sanitized" << "Failed" << "Partially Sanitized";
    } else if (isSandboxTable) {
        statusValues = QStringList() << "Malicious" << "Suspicious" << "Clean" << "Unknown";
    } else {
        statusValues = QStringList() << "Clean" << "Infected" << "Suspicious" << "Unknown";
    }
    
    QDateTime currentTime = QDateTime::currentDateTime();
    
    for (int i = 0; i < count; ++i) {
        int row = table->rowCount();
        table->insertRow(row);
        
        // Rastgele zaman (son 24 saat içinde)
        QDateTime timestamp = currentTime.addSecs(-1 * QRandomGenerator::global()->bounded(24 * 60 * 60));
        table->setItem(row, 0, new QTableWidgetItem(timestamp.toString("yyyy-MM-dd hh:mm:ss")));
        
        // Rastgele dosya adı
        QString fileName = fileTypes.at(QRandomGenerator::global()->bounded(fileTypes.size()));
        table->setItem(row, 1, new QTableWidgetItem(fileName));
        
        if (isVirusTotalTable) {
            // VirusTotal tablosu için özel sütun değerleri
            table->setItem(row, 2, new QTableWidgetItem(QString::number(QRandomGenerator::global()->bounded(10000))));
            table->setItem(row, 3, new QTableWidgetItem(QString("%1/%2").arg(QRandomGenerator::global()->bounded(10)).arg(56)));
            table->setItem(row, 4, new QTableWidgetItem(QString("f%1").arg(QRandomGenerator::global()->bounded(1000000000), 10, 10, QChar('0'))));
        } else if (isCdrTable) {
            // CDR tablosu için özel sütun değerleri
            table->setItem(row, 2, new QTableWidgetItem(QString("safe_%1").arg(fileName)));
            table->setItem(row, 3, new QTableWidgetItem(statusValues.at(QRandomGenerator::global()->bounded(statusValues.size()))));
            table->setItem(row, 4, new QTableWidgetItem(QString::number(QRandomGenerator::global()->bounded(120) + 1)));
        } else if (isSandboxTable) {
            // Sandbox tablosu için özel sütun değerleri
            table->setItem(row, 2, new QTableWidgetItem(QString::number(QRandomGenerator::global()->bounded(100))));
            table->setItem(row, 3, new QTableWidgetItem(statusValues.at(QRandomGenerator::global()->bounded(statusValues.size()))));
            table->setItem(row, 4, new QTableWidgetItem(QString::number(QRandomGenerator::global()->bounded(300) + 10)));
        } else {
            // Offline tarama tablosu için özel sütun değerleri
            table->setItem(row, 2, new QTableWidgetItem(QString::number(QRandomGenerator::global()->bounded(10000))));
            table->setItem(row, 3, new QTableWidgetItem(QString::number(QRandomGenerator::global()->bounded(5))));
            table->setItem(row, 4, new QTableWidgetItem(statusValues.at(QRandomGenerator::global()->bounded(statusValues.size()))));
        }
    }
}