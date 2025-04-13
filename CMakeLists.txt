cmake_minimum_required(VERSION 3.30)
project(WindowsAv)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Qt'nin bulunduğu yeri CMake'e bildir
set(Qt6_DIR "/Volumes/Crucial/QT/6.10.0/macos/lib/cmake/Qt6")
set(CMAKE_PREFIX_PATH "/Volumes/Crucial/QT/6.10.0/macos/lib/cmake/Qt6")

# Qt'nin include ve library dizinlerini ekle
include_directories("/Volumes/Crucial/QT/6.10.0/macos/include")
link_directories("/Volumes/Crucial/QT/6.10.0/macos/lib")

# Qt bileşenlerini bul
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Sql Network)
find_package(CURL REQUIRED)

add_executable(WindowsAv
        main.cpp
        Headers/HashCalculation.h
        Src/HashCalculation.cpp
        Headers/UserInterface.h
        Src/UserInterface.cpp
        Headers/DbManager.h
        Src/DbManager.cpp
        Headers/ApiManager.h
        Src/ApiManager.cpp
)

target_link_libraries(WindowsAv
        PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Sql
        Qt6::Network
        CURL::libcurl
)
