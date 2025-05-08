#include "../../Headers/Widgets/ResultsWidget.h"
#include <QDateTime>
#include <QGroupBox>
#include <QDebug>

ResultsWidget::ResultsWidget(QWidget* parent)
    : QWidget(parent),
      m_titleLabel(nullptr),
      m_detailedViewButton(nullptr),
      m_resultScrollArea(nullptr),
      m_detailedResultScrollArea(nullptr),
      m_apiLogGroup(nullptr),
      m_resultTextEdit(nullptr),
      m_detailedResultTextEdit(nullptr),
      m_apiLogTextEdit(nullptr),
      m_isDetailedViewVisible(false)
{
    createLayout();
    setupConnections();
}

void ResultsWidget::createLayout()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    
    // Sonuç bölümünün başlığı ve detaylı görünüm butonu yan yana
    QHBoxLayout* resultsTitleLayout = new QHBoxLayout();
    resultsTitleLayout->setSpacing(15);
    
    // Sonuçlar başlığı
    m_titleLabel = new QLabel(tr("Scan Results"), this);
    m_titleLabel->setObjectName("titleLabel");
    resultsTitleLayout->addWidget(m_titleLabel);
    resultsTitleLayout->addStretch();
    
    // Detaylı görünüm butonu
    m_detailedViewButton = new QPushButton(tr("Detailed Analysis"), this);
    m_detailedViewButton->setObjectName("secondaryButton");
    resultsTitleLayout->addWidget(m_detailedViewButton);
    mainLayout->addLayout(resultsTitleLayout);
    
    // Normal sonuçlar için scroll area
    m_resultScrollArea = new QScrollArea(this);
    m_resultScrollArea->setWidgetResizable(true);
    m_resultScrollArea->setFrameShape(QFrame::NoFrame);
    m_resultScrollArea->setObjectName("transparentScrollArea");
    
    m_resultScrollArea->setMinimumHeight(500);
    m_resultScrollArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    
    QWidget* resultContainer = new QWidget(m_resultScrollArea);
    QVBoxLayout* resultContainerLayout = new QVBoxLayout(resultContainer);
    resultContainerLayout->setContentsMargins(10, 15, 10, 15);
    
    m_resultTextEdit = new QPlainTextEdit();
    m_resultTextEdit->setReadOnly(true);
    setupTextEditStyle(m_resultTextEdit);
    m_resultTextEdit->setMinimumHeight(400);
    resultContainerLayout->addWidget(m_resultTextEdit);
    
    m_resultScrollArea->setWidget(resultContainer);
    mainLayout->addWidget(m_resultScrollArea);
    
    // Detaylı sonuçlar için ikinci bir scroll area (başlangıçta gizli)
    m_detailedResultScrollArea = new QScrollArea(this);
    m_detailedResultScrollArea->setWidgetResizable(true);
    m_detailedResultScrollArea->setFrameShape(QFrame::NoFrame);
    m_detailedResultScrollArea->setObjectName("transparentScrollArea");
    
    m_detailedResultScrollArea->setMinimumHeight(500);
    m_detailedResultScrollArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    
    QWidget* detailedResultContainer = new QWidget(m_detailedResultScrollArea);
    QVBoxLayout* detailedResultContainerLayout = new QVBoxLayout(detailedResultContainer);
    detailedResultContainerLayout->setContentsMargins(10, 15, 10, 15);
    
    m_detailedResultTextEdit = new QPlainTextEdit();
    m_detailedResultTextEdit->setReadOnly(true);
    setupTextEditStyle(m_detailedResultTextEdit);
    m_detailedResultTextEdit->setMinimumHeight(400);
    detailedResultContainerLayout->addWidget(m_detailedResultTextEdit);
    
    m_detailedResultScrollArea->setWidget(detailedResultContainer);
    m_detailedResultScrollArea->setVisible(false);
    mainLayout->addWidget(m_detailedResultScrollArea);
    
    // API log widget
    QGroupBox* apiGroup = new QGroupBox(tr("Low-Level Communication"), this);
    
    QVBoxLayout* apiLayout = new QVBoxLayout(apiGroup);
    m_apiLogTextEdit = new QPlainTextEdit();
    m_apiLogTextEdit->setReadOnly(true);
    setupTextEditStyle(m_apiLogTextEdit);
    m_apiLogTextEdit->setMinimumHeight(50);
    apiLayout->addWidget(m_apiLogTextEdit);
    
    m_apiLogGroup = apiGroup;
    mainLayout->addWidget(apiGroup);

    // Başlangıçta gizle
    this->setVisible(false);
    
    setLayout(mainLayout);
}

void ResultsWidget::setupConnections()
{
    connect(m_detailedViewButton, &QPushButton::clicked, this, &ResultsWidget::toggleDetailedView);
}

void ResultsWidget::setupTextEditStyle(QPlainTextEdit* textEdit)
{
    if (textEdit) {
        textEdit->setReadOnly(true);
        
        // Monospace font for better text alignment
        QFont font("Courier New");
        font.setStyleHint(QFont::Monospace);
        font.setPointSize(10);
        textEdit->setFont(font);
        
        // Styl settings
        textEdit->setFrameShape(QFrame::NoFrame);
        textEdit->setLineWrapMode(QPlainTextEdit::WidgetWidth);
        textEdit->setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
    }
}

void ResultsWidget::showResults(bool showDetailed)
{
    this->setVisible(true);
    m_resultScrollArea->setVisible(!showDetailed);
    m_detailedResultScrollArea->setVisible(showDetailed);
    m_isDetailedViewVisible = showDetailed;
    m_apiLogGroup->setVisible(true);
}

void ResultsWidget::toggleDetailedView()
{
    m_isDetailedViewVisible = !m_isDetailedViewVisible;
    m_resultScrollArea->setVisible(!m_isDetailedViewVisible);
    m_detailedResultScrollArea->setVisible(m_isDetailedViewVisible);
}

void ResultsWidget::showApiResponse(const QJsonObject& response)
{
    try {
        // Check if response is empty or invalid
        if (response.isEmpty()) {
            m_resultTextEdit->clear();
            m_resultTextEdit->appendPlainText("❌ Error: API response is empty or invalid.");
            m_apiLogTextEdit->appendPlainText(QString("\n📥 Received Response [%1]: Empty or invalid response")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
            return;
        }
        
        // Normal sonuçları göster
        m_resultTextEdit->clear();
        
        // Burada sonuçların formatlanması ve gösterilmesi kodu gelecek
        // ResultsView sınıfının showNormalResults ve showDetailedResults metodlarına benzer işlev
        
        // Örnek olarak basit formatlama:
        QStringList keys = response.keys();
        for (const QString& key : keys) {
            m_resultTextEdit->appendPlainText(QString("%1: %2")
                                            .arg(key)
                                            .arg(response[key].toString()));
        }
        
        // Detaylı sonuçları hazırla
        m_detailedResultTextEdit->clear();
        m_detailedResultTextEdit->appendPlainText(QJsonDocument(response).toJson(QJsonDocument::Indented));
        
        // API log'una yanıtı ekle
        m_apiLogTextEdit->appendPlainText(QString("\n📥 Received Response [%1]: Successful")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
    } 
    catch (const std::exception& e) {
        m_resultTextEdit->appendPlainText(QString("❌ Error: An issue occurred while processing the response: %1").arg(e.what()));
        m_apiLogTextEdit->appendPlainText(QString("\n📥 Error [%1]: %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(e.what()));
    } 
    catch (...) {
        m_resultTextEdit->appendPlainText("❌ Error: An unknown issue occurred while processing the response.");
        m_apiLogTextEdit->appendPlainText(QString("\n📥 Error [%1]: Unknown error")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
    }
}

void ResultsWidget::logApiRequest(const QString& endpoint)
{
    m_apiLogTextEdit->appendPlainText(QString("📤 %1 | Request: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(endpoint));
}

void ResultsWidget::logApiError(const QString& errorMessage)
{
    // API hatasını log ve sonuçlar bölümüne ekle
    m_apiLogTextEdit->appendPlainText(QString("\n❌ %1 | ERROR: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(errorMessage));
    
    // Ana sonuç bölümüne de hata mesajını ekle
    m_resultTextEdit->clear();
    m_resultTextEdit->appendPlainText("❌ API Error: " + errorMessage);
    m_resultTextEdit->appendPlainText("\nPlease check your internet connection or try again later.");
}