cmake_minimum_required(VERSION 3.0.0)
project(tls_server)

add_executable(tls_server main.cpp ../common.cpp)

set_target_properties(tls_server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/tls_server"
)

target_include_directories(tls_server PRIVATE
    ${CMAKE_SOURCE_DIR}
)

find_package(OpenSSL REQUIRED)
target_link_libraries(tls_server OpenSSL::SSL)

add_custom_command(TARGET tls_server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${SERVER_CERTS}
        $<TARGET_FILE_DIR:tls_server>
    )

add_custom_command(TARGET tls_server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/tls_server/temp"
    )

add_custom_command(TARGET tls_server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/tls_server/certs"
    )