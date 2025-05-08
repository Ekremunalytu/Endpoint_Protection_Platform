cmake_minimum_required(VERSION 3.28)

# Database modülü kaynak dosyaları
set(DATABASE_SOURCES
    Src/DbManager.cpp
)

# Database modülü başlık dosyaları
set(DATABASE_HEADERS
    Headers/DbManager.h
)

# Database kütüphanesi oluştur
add_library(Database STATIC ${DATABASE_SOURCES} ${DATABASE_HEADERS})

# Include dizinleri
target_include_directories(Database PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/Headers
    ${CMAKE_SOURCE_DIR}  # Projenin ana dizinini ekle (diğer modüllerin Headers erişimi için)
    ${CMAKE_SOURCE_DIR}/Interfaces/Headers
)

# Qt bağımlılıkları
target_link_libraries(Database PUBLIC
    Qt6::Network
    Qt6::Core
    Qt6::Sql
    Qt6::Concurrent
)