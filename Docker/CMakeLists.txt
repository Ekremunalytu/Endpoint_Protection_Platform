cmake_minimum_required(VERSION 3.28)

# Docker modülü kaynak dosyaları
set(DOCKER_SOURCES
    Src/DockerManager.cpp
    Src/DockerUIManager.cpp
)

# Docker modülü başlık dosyaları
set(DOCKER_HEADERS
    Headers/DockerManager.h
    Headers/DockerUIManager.h
)

# Docker kütüphanesi oluştur
add_library(Docker STATIC ${DOCKER_SOURCES} ${DOCKER_HEADERS})

# Include dizinleri
target_include_directories(Docker PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/Headers
    ${CMAKE_SOURCE_DIR}  # Projenin ana dizinini ekle (diğer modüllerin Headers erişimi için)
    ${CMAKE_SOURCE_DIR}/Interfaces/Headers
)

# Qt bağımlılıkları
target_link_libraries(Docker PUBLIC
    Qt6::Core
    Qt6::Network
    Qt6::Widgets
)