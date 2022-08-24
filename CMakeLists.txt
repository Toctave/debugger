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

option(TESTS "Build tests" ON)

if (TESTS)
  add_executable(tests
    src/tests.c)
  add_executable(test_child
    src/test_child.c)
  target_link_libraries(tests PRIVATE
    dwarf)
endif()

target_link_libraries(debugger PRIVATE
  dwarf
  dl
  )

