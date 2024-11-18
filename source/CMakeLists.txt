add_executable(thades main.cpp des/DES.cpp aes/AES.cpp OptionParser.cpp KeyHandler.cpp)

target_include_directories(thades PUBLIC "../includes")

find_package(OpenSSL REQUIRED)
target_link_libraries(thades OpenSSL::SSL OpenSSL::Crypto)

set_target_properties(thades PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/"
)