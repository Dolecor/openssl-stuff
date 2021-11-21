cmake_minimum_required(VERSION 3.0.0)
project(OpenSSL_test)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(CLIENT_CERTS ${CMAKE_CURRENT_SOURCE_DIR}/certs/client)
set(SERVER_CERTS ${CMAKE_CURRENT_SOURCE_DIR}/certs/server)

add_subdirectory(cert_create)
add_subdirectory(tls_server)
add_subdirectory(tls_client)
