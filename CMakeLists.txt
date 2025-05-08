cmake_minimum_required(VERSION 3.28)
project(Endpoint_Protection_Platform LANGUAGES CXX)

# C++ standard
set(CMAKE_CXX_STANDARD 20)

# Enable Qt features
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Platform-specific Qt paths
if(WIN32)
    # Windows için Qt dizinleri - ters eğik çizgiler düzeltildi
    set(Qt6_DIR "C:/Qt/6.10.0/msvc2022_64/lib/cmake/Qt6")
    set(CMAKE_PREFIX_PATH "${Qt6_DIR}")
elseif(APPLE)
    # macOS için Qt dizinleri
    set(Qt6_DIR "/Volumes/Crucial/QT/6.10.0/macos/lib/cmake/Qt6")
    set(CMAKE_PREFIX_PATH "${Qt6_DIR}")
endif()

# Qt bileşenlerini bul
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Sql Network Concurrent Charts)

# YARA konfigürasyonu
if(WIN32)
    find_path(YARA_INCLUDE_DIR
        NAMES yara.h
        HINTS "C:/Yara/include" "C:/vcpkg/packages/yara_x64-windows/include"
    )
    find_library(YARA_LIBRARY
        NAMES yara libyara
        HINTS "C:/Yara/lib" "C:/vcpkg/packages/yara_x64-windows/lib"
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

# Tüm alt modülleri ekle
add_subdirectory(Core)
add_subdirectory(Database)
add_subdirectory(Network)
add_subdirectory(Docker)
add_subdirectory(Security)
add_subdirectory(Scanning)
add_subdirectory(UI)
add_subdirectory(Interfaces)
add_subdirectory(Resources)

# Ana uygulama için kaynak dosyaları
set(SOURCE_FILES
    main.cpp
)

# Yürütülebilir oluştur
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

# Modülleri ana uygulamaya bağla
target_link_libraries(${PROJECT_NAME} PRIVATE
    Core
    Database
    Network
    Docker
    Security
    Scanning
    UI
    Resources
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Sql
    Qt6::Network
    Qt6::Concurrent
    Qt6::Charts
)

# Include dizinleri
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/Core/Headers
    ${CMAKE_SOURCE_DIR}/Database/Headers
    ${CMAKE_SOURCE_DIR}/Network/Headers
    ${CMAKE_SOURCE_DIR}/Docker/Headers
    ${CMAKE_SOURCE_DIR}/Security/Headers
    ${CMAKE_SOURCE_DIR}/Scanning/Headers
    ${CMAKE_SOURCE_DIR}/UI/Headers
    ${CMAKE_SOURCE_DIR}/Interfaces/Headers
)

# YARA bağlantısı
if(YARA_INCLUDE_DIR AND YARA_LIBRARY)
    target_include_directories(${PROJECT_NAME} PRIVATE ${YARA_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${YARA_LIBRARY})
else()
    message(FATAL_ERROR "Could not find YARA (headers or library)")
endif()

# Post-build: MalwareHashes dizinini çalıştırılabilirle aynı yere kopyala
if(EXISTS ${CMAKE_SOURCE_DIR}/MalwareHashes)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/MalwareHashes
            $<TARGET_FILE_DIR:${PROJECT_NAME}>/MalwareHashes
    )
endif()

# Post-build: Rules dizinini çalıştırılabilirle aynı yere kopyala
if(EXISTS ${CMAKE_SOURCE_DIR}/Rules)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/Rules
            $<TARGET_FILE_DIR:${PROJECT_NAME}>/Rules
    )
endif()