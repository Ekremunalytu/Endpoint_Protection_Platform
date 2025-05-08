#ifndef SIDEBARWIDGET_H
#define SIDEBARWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QMap>
#include <memory>

/**
 * @brief Sol kenar çubuğu widget'ı
 * Uygulamanın ana navigasyon menüsünü içerir
 */
class SidebarWidget : public QWidget {
    Q_OBJECT

public:
    /**
     * @brief Sayfalar için enum
     */
    enum class Page {
        OfflineScan,
        OnlineScan,
        CdrScan,
        Sandbox,
        ServiceStatus,
        History
    };
    
    /**
     * @brief Yapıcı metod
     * @param parent Üst widget
     */
    explicit SidebarWidget(QWidget* parent = nullptr);
    
    /**
     * @brief Belirli bir sayfayı aktif olarak ayarla
     * @param page Aktifleştirilecek sayfa
     */
    void setActivePage(Page page);

signals:
    /**
     * @brief Sayfa değiştiğinde sinyal verir
     * @param page Seçilen sayfa
     */
    void pageChanged(SidebarWidget::Page page);

private:
    void createLayout();
    void setupConnections();
    
    // Ekranlara karşılık gelen butonlar
    QMap<Page, QPushButton*> m_buttons;
    Page m_activePage;
};

#endif // SIDEBARWIDGET_H