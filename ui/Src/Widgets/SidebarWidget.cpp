#include "../../Headers/Widgets/SidebarWidget.h"

SidebarWidget::SidebarWidget(QWidget* parent)
    : QWidget(parent),
      m_activePage(Page::OfflineScan)
{
    setObjectName("sidebarWidget");
    setFixedWidth(220);
    
    createLayout();
    setupConnections();
}

void SidebarWidget::createLayout()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setSpacing(0);
    layout->setContentsMargins(0, 20, 0, 20);

    // Sidebar butonu oluşturma için lambda fonksiyon
    auto createSidebarButton = [this, layout](const QString& text, Page page, bool checked = false) -> QPushButton* {
        QPushButton* btn = new QPushButton(text, this);
        btn->setCheckable(true);
        btn->setChecked(checked);
        btn->setIconSize(QSize(20, 20));
        
        // Objektif ile QSS bağlantısı
        btn->setObjectName("coloredSidebarButton");
        
        layout->addWidget(btn);
        m_buttons[page] = btn;
        return btn;
    };

    // Sidebar butonları oluşturuluyor
    createSidebarButton(tr("Offline Scan"), Page::OfflineScan, true);
    createSidebarButton(tr("Online Scan"), Page::OnlineScan);
    createSidebarButton(tr("CDR Scan"), Page::CdrScan);
    createSidebarButton(tr("Sandbox"), Page::Sandbox);
    createSidebarButton(tr("Service Status"), Page::ServiceStatus);

    // Sidebar'ın alt kısmında geçmiş butonu
    layout->addStretch();
    createSidebarButton(tr("History"), Page::History);
    
    // Qt Stylesheet'te kapsayıcı stil tanımlanabilir
    setStyleSheet("QPushButton#coloredSidebarButton { background-color: #1e88e5; }");
}

void SidebarWidget::setupConnections()
{
    // Tüm butonlar için bağlantıları kur
    for (auto it = m_buttons.begin(); it != m_buttons.end(); ++it) {
        const Page page = it.key();
        QPushButton* btn = it.value();
        
        connect(btn, &QPushButton::clicked, [this, page]() {
            setActivePage(page);
            emit pageChanged(page);
        });
    }
}

void SidebarWidget::setActivePage(Page page)
{
    // Önceki aktif sayfayı temizle
    if (m_buttons.contains(m_activePage)) {
        m_buttons[m_activePage]->setChecked(false);
    }
    
    // Yeni sayfayı aktifleştir
    if (m_buttons.contains(page)) {
        m_buttons[page]->setChecked(true);
        m_activePage = page;
    }
}