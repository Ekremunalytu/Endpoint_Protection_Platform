#ifndef HISTORYDIALOG_H
#define HISTORYDIALOG_H

#include <QDialog>
#include <QJsonArray>
#include <QJsonObject>
#include <QTableWidget> // Added include

// Forward declaration of Ui::HistoryDialog
namespace Ui {
class HistoryDialog;
}

class HistoryDialog : public QDialog
{
    Q_OBJECT

public:
    explicit HistoryDialog(QWidget *parent = nullptr);
    ~HistoryDialog();

private slots:
    void onTabChanged(int index);
    void onClearHistoryClicked();
    void onExportHistoryClicked();
    // Add slots for view buttons in tables if dynamic connections are needed

private:
    void setupConnections();
    void loadHistory(); // Combined method to load all history types
    void populateTable(QTableWidget* table, const QJsonArray& data, const QStringList& headers);
    // Specific load methods for each tab if needed, or handle in loadHistory()
    // void loadScanHistory();
    // void loadVtHistory();
    // void loadCdrHistory();
    // void loadSandboxHistory()

    Ui::HistoryDialog *ui;
    // DbManager* dbManager_; // If history is fetched from a database
};

#endif // HISTORYDIALOG_H
