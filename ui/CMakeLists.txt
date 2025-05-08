cmake_minimum_required(VERSION 3.28)
project(UI LANGUAGES CXX)

# UI modülü için kaynaklar
set(SOURCES
    Src/UserInterface.cpp
    Src/MainWindow.cpp
    Src/Dialogs/ApiKeyDialog.cpp                  # Added
    Src/Dialogs/DockerImageSelectionDialog.cpp    # Added
    Src/Dialogs/HistoryDialog.cpp                 # Added
    Src/Dialogs/ServiceStatusDialog.cpp           # Added
    Src/Widgets/ScanWidget.cpp
    Src/Widgets/HistoryWidget.cpp
    Src/Widgets/DashboardWidget.cpp
    Src/Widgets/SettingsWidget.cpp
    Src/Widgets/ResultsWidget.cpp                 # Added
    Src/Widgets/SidebarWidget.cpp                 # Added
)

# UI modülü için header'lar
set(HEADERS
    Headers/UserInterface.h
    Headers/MainWindow.h
    Headers/Dialogs/ApiKeyDialog.h                  # Added
    Headers/Dialogs/DockerImageSelectionDialog.h    # Added
    Headers/Dialogs/HistoryDialog.h                 # Added
    Headers/Dialogs/ServiceStatusDialog.h           # Added
    Headers/Widgets/ScanWidget.h
    Headers/Widgets/HistoryWidget.h
    Headers/Widgets/DashboardWidget.h
    Headers/Widgets/SettingsWidget.h
    Headers/Widgets/ResultsWidget.h                 # Added
    Headers/Widgets/SidebarWidget.h                 # Added
)

# Qt Charts modülü gerekiyor (DashboardWidget için)
find_package(Qt6 REQUIRED COMPONENTS Charts)

# Statik kütüphane oluştur
add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})

# Hedef dizinler
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/Core/Headers
    ${CMAKE_SOURCE_DIR}/Database/Headers
    ${CMAKE_SOURCE_DIR}/Network/Headers
    ${CMAKE_SOURCE_DIR}/Docker/Headers
    ${CMAKE_SOURCE_DIR}/Security/Headers
    ${CMAKE_SOURCE_DIR}/Scanning/Headers
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/Interfaces/Headers
    ${CMAKE_SOURCE_DIR}/UI/Headers
)

# Qt bileşenlerini bağla
target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Sql
    Qt6::Charts
    Qt6::Network
    Qt6::Concurrent  # Add Qt Concurrent module
    Network
    Database         # Add link to Database module
)