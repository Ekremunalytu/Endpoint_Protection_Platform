cmake_minimum_required(VERSION 3.28)

# Interfaces modülü başlık dosyaları
set(INTERFACES_HEADERS
    Headers/IApiManager.h
    Headers/IDbManager.h
    Headers/IYaraRuleManager.h
    Headers/ICdrManager.h
    Headers/ISandboxManager.h
    Headers/IDockerManager.h
)

# Interfaces kütüphanesi oluştur (sadece başlıklar olacak)
add_library(Interfaces INTERFACE)

# Include dizinleri
target_include_directories(Interfaces INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/Headers
    ${CMAKE_SOURCE_DIR}  # Projenin ana dizinini ekle (diğer modüllerin Headers erişimi için)
)

# Propagate Qt6::Sql dependency
target_link_libraries(Interfaces INTERFACE Qt6::Sql)