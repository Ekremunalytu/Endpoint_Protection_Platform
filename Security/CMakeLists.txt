cmake_minimum_required(VERSION 3.28)

# Security modülü kaynak dosyaları
set(SECURITY_SOURCES
    Src/YaraRuleManager.cpp
    Src/CdrManager.cpp
    Src/SandboxManager.cpp
)

# Security modülü başlık dosyaları
set(SECURITY_HEADERS
    Headers/YaraRuleManager.h
    Headers/CdrManager.h
    Headers/SandboxManager.h
)

# Security kütüphanesi oluştur
add_library(Security STATIC ${SECURITY_SOURCES} ${SECURITY_HEADERS})

# Include dizinleri
target_include_directories(Security PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/Headers
    ${CMAKE_SOURCE_DIR}  # Projenin ana dizinini ekle (diğer modüllerin Headers erişimi için)
    ${CMAKE_SOURCE_DIR}/Interfaces/Headers
    ${CMAKE_SOURCE_DIR}/Core/Headers # Core modülünün başlık dosyalarını ekle
)

# Qt bağımlılıkları
target_link_libraries(Security PUBLIC
    Qt6::Core
    Interfaces # Add Interfaces library
)

# YARA bağımlılığını ekle
if(YARA_INCLUDE_DIR AND YARA_LIBRARY)
    target_include_directories(Security PUBLIC ${YARA_INCLUDE_DIR})
    target_link_libraries(Security PUBLIC ${YARA_LIBRARY})
endif()