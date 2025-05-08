cmake_minimum_required(VERSION 3.28)

# Core modülü kaynak dosyaları
set(CORE_SOURCES
    Src/ConfigManager.cpp
    Src/HashCalculation.cpp
    Src/ServiceLocator.cpp
    Src/ApplicationStartup.cpp
)

# Core modülü başlık dosyaları 
set(CORE_HEADERS
    Headers/ConfigManager.h
    Headers/HashCalculation.h
    Headers/ServiceLocator.h
    Headers/ThreadPool.h
    Headers/ApplicationStartup.h
)

# Core kütüphanesi oluştur
add_library(Core STATIC ${CORE_SOURCES} ${CORE_HEADERS})

# Include dizinleri
target_include_directories(Core PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/Headers
    ${CMAKE_SOURCE_DIR}  # Projenin ana dizinini ekle (diğer modüllerin Headers erişimi için)
    ${CMAKE_SOURCE_DIR}/Interfaces/Headers
)

# Qt bağımlılıkları
target_link_libraries(Core PUBLIC
    Qt6::Core
    Qt6::Concurrent
    Qt6::Widgets
    Network
    Security
    Database
    Docker
    Interfaces # Add Interfaces library
)