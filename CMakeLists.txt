cmake_minimum_required(VERSION 3.10)

project(debugger)

add_executable(debugger
  src/main.c
  )

add_executable(child
  src/child.c
  )

target_link_libraries(debugger PRIVATE
  dwarf
  )

