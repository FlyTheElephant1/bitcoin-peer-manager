cmake_minimum_required(VERSION 3.14)
project(bitcoin_peer_scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Generate git_version.h at build time (every make)
set(GIT_VERSION_H ${CMAKE_BINARY_DIR}/git_version.h)
add_custom_target(git_version
  COMMAND ${CMAKE_SOURCE_DIR}/gen_git_version.sh ${GIT_VERSION_H}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "Generating git_version.h"
  VERBATIM
)

include_directories(${CMAKE_BINARY_DIR})

include(FetchContent)
FetchContent_Declare(
  ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG v5.0.0
)
FetchContent_MakeAvailable(ftxui)

add_executable(peer_daemon peer_daemon.cpp)
add_dependencies(peer_daemon git_version)
set_source_files_properties(peer_daemon.cpp PROPERTIES OBJECT_DEPENDS ${GIT_VERSION_H})
target_link_libraries(peer_daemon PRIVATE pthread rt)

add_executable(peer_display peer_display.cpp)
add_dependencies(peer_display git_version)
set_source_files_properties(peer_display.cpp PROPERTIES OBJECT_DEPENDS ${GIT_VERSION_H})
target_link_libraries(peer_display PRIVATE ftxui::screen ftxui::dom ftxui::component pthread rt)
