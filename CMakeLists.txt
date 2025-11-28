cmake_minimum_required(VERSION 3.13)
project(KUMPIL2R)

find_package(LLVM REQUIRED CONFIG)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(HandleLLVMOptions)
include(AddLLVM)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

# 타겟 중복 방지
if (NOT TARGET kumpil2r)
  add_library(kumpil2r MODULE kumpil2r.cc)
endif()

# ===== lib/ 폴더에 소스가 있을 때만 런타임 라이브러리 빌드 =====
file(GLOB_RECURSE RUNTIME_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_SOURCE_DIR}/lib/*.c"
  "${CMAKE_SOURCE_DIR}/lib/*.cc"
  "${CMAKE_SOURCE_DIR}/lib/*.cpp"
)

if (RUNTIME_SOURCES)
  add_library(kumpil2r_rt STATIC ${RUNTIME_SOURCES})
  target_compile_options(kumpil2r_rt PRIVATE -O2 -fPIC -fvisibility=hidden -fno-sanitize=all)
  set_target_properties(kumpil2r_rt PROPERTIES POSITION_INDEPENDENT_CODE ON)

  find_package(Threads REQUIRED)
  if (UNIX AND NOT APPLE)
    target_link_libraries(kumpil2r_rt PUBLIC Threads::Threads dl)
  else()
    target_link_libraries(kumpil2r_rt PUBLIC Threads::Threads)
  endif()
else()
  message(WARNING "lib/ 폴더에서 런타임 소스를 찾지 못했습니다. kumpil2r_rt 생성을 건너뜁니다.")
endif()