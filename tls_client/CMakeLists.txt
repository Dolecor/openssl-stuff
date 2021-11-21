cmake_minimum_required(VERSION 3.0.0)
project(tls_client)

add_executable(tls_client main.cpp ../common.cpp)

set_target_properties(tls_client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/tls_client"
    )

target_include_directories(tls_client PRIVATE
    ${CMAKE_SOURCE_DIR}
    )

find_package(OpenSSL REQUIRED)
target_link_libraries(tls_client OpenSSL::SSL)

add_custom_command(TARGET tls_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CLIENT_CERTS}
        $<TARGET_FILE_DIR:tls_client>
    )

add_custom_command(TARGET tls_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/tls_client/temp"
    )

add_custom_command(TARGET tls_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/tls_client/certs"
    )
