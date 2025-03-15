cmake_minimum_required(VERSION 3.30)
project(Endpoint_Protection_Platform)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_PREFIX_PATH "/Volumes/Crucial/QT/6.10.0/macos/lib/cmake/Qt6")

find_package(Qt6 COMPONENTS
  Core
  Gui
  Widgets
        Sql
  REQUIRED)



add_executable(Endpoint_Protection_Platform main.cpp
        Headers/HashCalculation.h
        Src/HashCalculation.cpp
        Headers/UserInterface.h
        Src/UserInterface.cpp
        Headers/DbManager.h
        Src/DbManager.cpp
)
target_link_libraries(Endpoint_Protection_Platform
        PRIVATE
  Qt::Core
        Qt6::Sql
  Qt::Gui
  Qt::Widgets
)

