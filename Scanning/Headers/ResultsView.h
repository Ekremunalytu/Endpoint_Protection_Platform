#ifndef RESULTSVIEW_H
#define RESULTSVIEW_H

#include <QObject>
#include <QPlainTextEdit>
#include <QJsonObject>

class ResultsView : public QObject
{
    Q_OBJECT

public:
    explicit ResultsView(QObject *parent = nullptr);
    ~ResultsView();

    // UI bileşenlerini ayarla
    void setResultTextEdit(QPlainTextEdit* resultTextEdit);
    void setDetailedResultTextEdit(QPlainTextEdit* detailedTextEdit);
    
    // Sonuç görüntüleme yöntemleri
    void showNormalResults(const QJsonObject& response);
    void showDetailedResults(const QJsonObject& response);
    void setupTextEditStyle(QPlainTextEdit* textEdit);
    
private:
    QPlainTextEdit* m_resultTextEdit;
    QPlainTextEdit* m_detailedResultTextEdit;
};

#endif // RESULTSVIEW_H