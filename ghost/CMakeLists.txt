cmake_minimum_required(VERSION 3.10)
project(VortexAgent)

set(CMAKE_CXX_STANDARD 17)

# Add source files
file(GLOB SOURCES "src/*.cpp")

# Define executable
add_executable(vortex_agent ${SOURCES})

# Future: Add nlohmann_json if needed
# target_include_directories(vortex_agent PRIVATE include)
