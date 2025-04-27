cmake_minimum_required(VERSION 3.28)
project(Endpoint_Protection_Platform)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Qt'nin bulunduğu yeri CMake'e bildir
set(Qt6_DIR "/Volumes/Crucial/QT/6.10.0/macos/lib/cmake/Qt6")
set(CMAKE_PREFIX_PATH "/Volumes/Crucial/QT/6.10.0/macos/lib/cmake/Qt6")

# Qt'nin include ve library dizinlerini ekle
include_directories(
    ${CMAKE_SOURCE_DIR}
    "/Volumes/Crucial/QT/6.10.0/macos/include"
    "/Volumes/Crucial/QT/6.10.0/macos/lib"
)

# Qt bileşenlerini bul
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Sql Network)

add_executable(Endpoint_Protection_Platform
    main.cpp
    Headers/HashCalculation.h
    Src/HashCalculation.cpp
    Headers/UserInterface.h
    Src/UserInterface.cpp
    Headers/DbManager.h
    Src/DbManager.cpp
    Headers/ApiManager.h
    Headers/ConfigManager.h
    Src/ConfigManager.cpp
    Headers/YaraRuleManager.h
    Src/YaraRuleManager.cpp
)

target_link_libraries(Endpoint_Protection_Platform
    PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Sql
    Qt6::Network
)

# Derleme sırasında Qt başlık dosyalarını bulabilmesi için
target_include_directories(Endpoint_Protection_Platform PRIVATE
    ${CMAKE_SOURCE_DIR}
    "/Volumes/Crucial/QT/6.10.0/macos/include"
)

find_path(YARA_INCLUDE_DIR
    NAMES yara.h
    HINTS /opt/homebrew/include /usr/local/include
)
find_library(YARA_LIBRARY
    NAMES yara
    HINTS /opt/homebrew/lib /usr/local/lib
)
if (YARA_INCLUDE_DIR AND YARA_LIBRARY)
    target_include_directories(Endpoint_Protection_Platform PRIVATE ${YARA_INCLUDE_DIR})
    target_link_libraries(Endpoint_Protection_Platform PRIVATE ${YARA_LIBRARY})
else()
    message(FATAL_ERROR "Could not find YARA (headers or library)")
endif()
