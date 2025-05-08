cmake_minimum_required(VERSION 3.28)

# Resources kaynak dosyaları
set(RESOURCES_FILES
    resources.qrc
)

# Resources kütüphanesi oluştur
add_library(Resources STATIC ${RESOURCES_FILES})

# Qt bağımlılıkları
target_link_libraries(Resources PUBLIC
    Qt6::Core
)