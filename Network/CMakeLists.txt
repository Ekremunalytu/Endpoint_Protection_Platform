cmake_minimum_required(VERSION 3.28)

# Network modülü kaynak dosyaları
set(NETWORK_SOURCES
    Src/ApiManager.cpp
)

# Network modülü başlık dosyaları
set(NETWORK_HEADERS
    Headers/ApiManager.h
)

# Network kütüphanesi oluştur
add_library(Network STATIC ${NETWORK_SOURCES} ${NETWORK_HEADERS})

# Include dizinleri
target_include_directories(Network PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/Headers
    ${CMAKE_SOURCE_DIR}  # Projenin ana dizinini ekle (diğer modüllerin Headers erişimi için)
    ${CMAKE_SOURCE_DIR}/Interfaces/Headers
    ${CMAKE_SOURCE_DIR}/Core/Headers # Core modülünün başlık dosyalarını ekle
)

# Qt bağımlılıkları
target_link_libraries(Network PUBLIC
    Qt6::Core
    Qt6::Network

)