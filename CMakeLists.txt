cmake_minimum_required(VERSION 3.28)
project(Endpoint_Protection_Platform LANGUAGES CXX)

# C++ standard
set(CMAKE_CXX_STANDARD 20)

# Enable Qt features
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Platform-specific Qt paths  # <<< Değiştirilmiş: tek QT_ROOT yerine direkt Qt6_DIR kullanımı ve CMAKE_PREFIX_PATH ayarı
if(WIN32)
    # Windows için Qt dizinleri
    set(Qt6_DIR "C:/Qt/6.10.0/msvc2022_arm64/lib/cmake/Qt6")  # güncellendi
    set(CMAKE_PREFIX_PATH "${Qt6_DIR}")                       # güncellendi
elseif(APPLE)
    # macOS için Qt dizinleri
    set(Qt6_DIR "/Volumes/Crucial/QT/6.10.0/macos/lib/cmake/Qt6")  # güncellendi
    set(CMAKE_PREFIX_PATH "${Qt6_DIR}")                              # güncellendi
endif()

# Qt bileşenlerini bul
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Sql Network Concurrent)

# Kaynak ve başlık dosyaları
set(SOURCE_FILES
    main.cpp
    Src/HashCalculation.cpp
    Src/UserInterface.cpp
    Src/DbManager.cpp
    Src/ConfigManager.cpp
    Src/YaraRuleManager.cpp
    Src/ApiManager.cpp
)

set(HEADER_FILES
    Headers/HashCalculation.h
    Headers/UserInterface.h
    Headers/DbManager.h
    Headers/ApiManager.h
    Headers/ConfigManager.h
    Headers/YaraRuleManager.h
)

# Yürütülebilir oluştur
add_executable(${PROJECT_NAME}
    ${SOURCE_FILES}
    ${HEADER_FILES}
)

# Qt kütüphanelerini linkle
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Sql
        Qt6::Network
        Qt6::Concurrent
)

# Include dizinleri (proje ve Başlık klasörü)  # <<< Değiştirilmiş: include_directories -> target_include_directories ve Headers klasörü eklendi
if(WIN32)
    target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}                  # eklendi
        ${CMAKE_SOURCE_DIR}/Headers         # eklendi
        "C:/Qt/6.6.0/msvc2019_64/include"
        "C:/Qt/6.6.0/msvc2019_64/lib"
    )
elseif(APPLE)
    target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}                  # eklendi
        ${CMAKE_SOURCE_DIR}/Headers         # eklendi
        "/Volumes/Crucial/QT/6.10.0/macos/include"
        "/Volumes/Crucial/QT/6.10.0/macos/lib"
    )
endif()

# YARA konfigürasyonu
if(WIN32)
    find_path(YARA_INCLUDE_DIR
        NAMES yara.h
        HINTS C:/Yara/include "C:/Program Files/Yara/include"
    )
    find_library(YARA_LIBRARY
        NAMES yara
        HINTS C:/Yara/lib "C:/Program Files/Yara/lib"
    )
elseif(APPLE)
    find_path(YARA_INCLUDE_DIR
        NAMES yara.h
        HINTS /opt/homebrew/include /usr/local/include
    )
    find_library(YARA_LIBRARY
        NAMES yara
        HINTS /opt/homebrew/lib /usr/local/lib
    )
endif()

if(YARA_INCLUDE_DIR AND YARA_LIBRARY)
    target_include_directories(${PROJECT_NAME} PRIVATE ${YARA_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${YARA_LIBRARY})
else()
    message(FATAL_ERROR "Could not find YARA (headers or library)")
endif()

# Post-build: MalwareHashes dizinini çalıştırılabilirle aynı yere kopyala
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/MalwareHashes
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/MalwareHashes
)