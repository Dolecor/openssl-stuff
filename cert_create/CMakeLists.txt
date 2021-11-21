cmake_minimum_required(VERSION 3.0.0)
project(cert_create)

add_executable(cert_create main.cpp)

set_target_properties(cert_create PROPERTIES
RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cert_create"
)

find_package(OpenSSL REQUIRED)
target_link_libraries(cert_create OpenSSL::SSL)
