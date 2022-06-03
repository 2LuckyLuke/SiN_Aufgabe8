cmake_minimum_required(VERSION 3.20)
project(SiN_Aufgabe8)

file(GLOB SRC_FILES
        "cryptopp860/*.cpp"
        )

set(CMAKE_CXX_STANDARD 14)

target_sources(SiN_Aufgabe8 PUBLIC ${SRC_FILES})

add_executable(SiN_Aufgabe8 main.cpp)
