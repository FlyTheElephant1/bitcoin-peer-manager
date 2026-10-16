cmake_minimum_required(VERSION 3.14)
project(bitcoin_peer_scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG v5.0.0
)
FetchContent_MakeAvailable(ftxui)

add_executable(peer_daemon peer_daemon.cpp)
target_link_libraries(peer_daemon PRIVATE pthread rt)

add_executable(peer_display peer_display.cpp)
target_link_libraries(peer_display PRIVATE ftxui::screen ftxui::dom ftxui::component pthread rt)
