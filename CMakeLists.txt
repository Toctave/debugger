cmake_minimum_required(VERSION 3.10)

project(debugger)

add_executable(debugger
  src/main.c
  src/logging.c
  src/memory.c
  src/platform_linux.c
  )

add_executable(child
  src/child.c
  )

add_executable(tests
  src/tests.c)

target_link_libraries(debugger PRIVATE
  dwarf
  )

