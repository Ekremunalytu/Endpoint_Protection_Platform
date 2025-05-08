cmake_minimum_required(VERSION 3.28)

# Scanning modülü kaynak dosyaları
set(SCANNING_SOURCES
    Src/ScanManager.cpp
    Src/ResultsView.cpp
)

# Scanning modülü başlık dosyaları
set(SCANNING_HEADERS
    Headers/ScanManager.h
    Headers/ResultsView.h
)

# Scanning kütüphanesi oluştur
add_library(Scanning STATIC ${SCANNING_SOURCES} ${SCANNING_HEADERS})

# Include dizinleri
target_include_directories(Scanning PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/Headers
    ${CMAKE_SOURCE_DIR}  # Projenin ana dizinini ekle (diğer modüllerin Headers erişimi için)
    ${CMAKE_SOURCE_DIR}/Interfaces/Headers
    ${CMAKE_SOURCE_DIR}/Core/Headers # Core modülünün başlık dosyalarını ekle
)

# Qt bağımlılıkları
target_link_libraries(Scanning PUBLIC
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Concurrent
    Interfaces # Add Interfaces library
)