#ifndef RESULTSWIDGET_H
#define RESULTSWIDGET_H

#include <QWidget>
#include <QPlainTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QJsonObject>

/**
 * @brief Tarama sonuçlarını görüntüleyen widget
 * Normal ve detaylı sonuçları görüntüler, API iletişim loglarını tutar
 */
class ResultsWidget : public QWidget {
    Q_OBJECT

public:
    /**
     * @brief Yapıcı metod
     * @param parent Üst widget
     */
    explicit ResultsWidget(QWidget* parent = nullptr);

    /**
     * @brief Destructor
     */
    ~ResultsWidget() override = default;

    /**
     * @brief Sonuç görüntüleme alanını döndürür
     * @return Sonuç metin alanı
     */
    QPlainTextEdit* getResultTextEdit() const { return m_resultTextEdit; }

    /**
     * @brief Detaylı sonuç görüntüleme alanını döndürür
     * @return Detaylı sonuç metin alanı
     */
    QPlainTextEdit* getDetailedResultTextEdit() const { return m_detailedResultTextEdit; }

    /**
     * @brief API loglarını gösteren metin alanını döndürür
     * @return API log metin alanı
     */
    QPlainTextEdit* getApiLogTextEdit() const { return m_apiLogTextEdit; }

    /**
     * @brief Sonuçları görünür yapar
     * @param showDetailed Detaylı görünüm gösterilsin mi
     */
    void showResults(bool showDetailed = false);

public slots:
    /**
     * @brief API yanıtı alındığında sonuçları göster
     * @param response API yanıtı
     */
    void showApiResponse(const QJsonObject& response);

    /**
     * @brief API isteği gönderildiğinde log tutma
     * @param endpoint İstek gönderilen endpoint
     */
    void logApiRequest(const QString& endpoint);

    /**
     * @brief API hatası olduğunda log tutma
     * @param errorMessage Hata mesajı
     */
    void logApiError(const QString& errorMessage);

    /**
     * @brief Detaylı görünümü göster/gizle
     */
    void toggleDetailedView();

private:
    void createLayout();
    void setupConnections();
    void setupTextEditStyle(QPlainTextEdit* textEdit);

    // UI bileşenleri
    QLabel* m_titleLabel;
    QPushButton* m_detailedViewButton;
    QScrollArea* m_resultScrollArea;
    QScrollArea* m_detailedResultScrollArea;
    QWidget* m_apiLogGroup;
    
    // Metin alanları
    QPlainTextEdit* m_resultTextEdit;
    QPlainTextEdit* m_detailedResultTextEdit;
    QPlainTextEdit* m_apiLogTextEdit;

    bool m_isDetailedViewVisible;
};

#endif // RESULTSWIDGET_H