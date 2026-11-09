cmake_minimum_required(VERSION 3.16)
project(HydaVM CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(HYDA_WARNINGS "Enable high warning level" ON)
option(HYDA_BUILD_LIFTER "Build the x86 -> VM bytecode lifter" OFF)

add_library(hyda_vm STATIC
  src/core/thread.cpp
  src/guard/api_resolve.cpp
  src/ir/ir_codegen.cpp
  src/mutate/fuse.cpp
  src/mutate/mutate.cpp
  src/mutate/obf.cpp
  src/vm/dispatch_asm.cpp
  src/vm/fpstate.cpp
  src/vm/gate.cpp
  src/vm/handlers.cpp
  src/vm/ring.cpp
  src/vm/vm.cpp
  src/vm/vm2.cpp
)
target_include_directories(hyda_vm PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

if(WIN32 AND NOT MSVC)
  set_source_files_properties(src/vm/dispatch_asm.cpp PROPERTIES
    COMPILE_OPTIONS "-fno-asynchronous-unwind-tables;-fno-unwind-tables")
endif()

if(HYDA_VM_SEED)
  target_compile_definitions(hyda_vm PUBLIC "HYDA_VM_SEED=${HYDA_VM_SEED}")
endif()

if(NOT MSVC)
  target_compile_options(hyda_vm PRIVATE -fno-strict-aliasing)
  target_compile_options(hyda_vm PRIVATE -fno-jump-tables)
  target_compile_options(hyda_vm PRIVATE
    -fno-builtin-strlen -fno-tree-loop-distribute-patterns)
  target_compile_options(hyda_vm PRIVATE -fno-math-errno)
  if(HYDA_WARNINGS)
    target_compile_options(hyda_vm PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
endif()

enable_testing()

add_executable(test_vm tests/test_vm.cpp)
target_link_libraries(test_vm PRIVATE hyda_vm)
if(NOT MSVC AND HYDA_WARNINGS)
  target_compile_options(test_vm PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()
add_test(NAME vm_host COMMAND test_vm)

if(WIN32)
  add_executable(vm_selftest runtime/win/vm_selftest.cpp)
  target_link_libraries(vm_selftest PRIVATE hyda_vm)
  if(NOT MSVC AND HYDA_WARNINGS)
    target_compile_options(vm_selftest PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
  add_test(NAME vm_pe COMMAND vm_selftest)

  add_executable(pe_target tests/pe_target.cpp runtime/win/hyda_vm_entry.cpp)
  target_link_libraries(pe_target PRIVATE hyda_vm)
  if(NOT MSVC)
    target_link_options(pe_target PRIVATE -Wl,--file-alignment,0x1000)
    target_compile_options(pe_target PRIVATE -fno-ipa-cp-clone)
  endif()
  if(NOT MSVC AND HYDA_WARNINGS)
    target_compile_options(pe_target PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()

  add_executable(pe_target_hooktest tests/pe_target.cpp
                 runtime/win/hyda_vm_entry.cpp)
  target_link_libraries(pe_target_hooktest PRIVATE hyda_vm)
  if(NOT MSVC)
    target_link_options(pe_target_hooktest PRIVATE -Wl,--file-alignment,0x1000)
  endif()
  target_compile_definitions(pe_target_hooktest PRIVATE HYDA_HOOKTEST=1)
  if(NOT MSVC)
    target_compile_options(pe_target_hooktest PRIVATE -fno-ipa-cp-clone)
  endif()
  if(NOT MSVC AND HYDA_WARNINGS)
    target_compile_options(pe_target_hooktest PRIVATE -Wall -Wextra
                           -Wno-unused-parameter)
  endif()

  add_executable(pe_target_adbgtest tests/pe_target.cpp
                 runtime/win/hyda_vm_entry.cpp)
  target_link_libraries(pe_target_adbgtest PRIVATE hyda_vm)
  if(NOT MSVC)
    target_link_options(pe_target_adbgtest PRIVATE -Wl,--file-alignment,0x1000)
  endif()
  target_compile_definitions(pe_target_adbgtest PRIVATE HYDA_ADBGTEST=1)
  if(NOT MSVC)
    target_compile_options(pe_target_adbgtest PRIVATE -fno-ipa-cp-clone)
  endif()
  if(NOT MSVC AND HYDA_WARNINGS)
    target_compile_options(pe_target_adbgtest PRIVATE -Wall -Wextra
                           -Wno-unused-parameter)
  endif()

  add_library(x64dbg SHARED tests/adbg_dummy.cxx)
  set_target_properties(x64dbg PROPERTIES PREFIX "")
endif()

if(HYDA_BUILD_LIFTER)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(CAPSTONE REQUIRED capstone)

  add_library(hyda_lift STATIC lifter/lift.cpp lifter/native_island.cpp)
  target_include_directories(hyda_lift PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/lifter" ${CAPSTONE_INCLUDE_DIRS})
  target_link_libraries(hyda_lift PUBLIC hyda_vm ${CAPSTONE_LIBRARIES})
  if(NOT MSVC AND HYDA_WARNINGS)
    target_compile_options(hyda_lift PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()

  add_executable(hyda_lifter lifter/main.cpp)
  target_link_libraries(hyda_lifter PRIVATE hyda_lift)

  add_executable(test_lifter tests/test_lifter.cpp)
  target_link_libraries(test_lifter PRIVATE hyda_lift)
  add_test(NAME lift_host COMMAND test_lifter)

  add_executable(hyda_protect
    tools/protect/main.cpp
    tools/protect/cli.cpp
    tools/protect/handlers.cpp
    tools/protect/layout.cpp
    tools/protect/protector.cpp
  )
  target_link_libraries(hyda_protect PRIVATE hyda_lift)
  target_include_directories(hyda_protect PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/tools/protect")

  find_program(HYDA_WINE_EMU wine)
  if(NOT HYDA_PE_TARGET_EXE)
    set(HYDA_PE_TARGET_EXE "${CMAKE_CURRENT_SOURCE_DIR}/build-win/pe_target.exe")
  endif()
  if(HYDA_WINE_EMU AND EXISTS "${HYDA_PE_TARGET_EXE}")
    add_test(NAME pe_e2e
      COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/tools/protect_e2e.sh"
              "${CMAKE_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/build-win")
  endif()
endif()