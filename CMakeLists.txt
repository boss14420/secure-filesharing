cmake_minimum_required(VERSION 2.8.10)
project(securesharing)

ADD_CUSTOM_TARGET(debug
  COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug ${CMAKE_SOURCE_DIR}
  COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target all
  COMMENT "Switch CMAKE_BUILD_TYPE to Debug"
  )

ADD_CUSTOM_TARGET(release
  COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Release ${CMAKE_SOURCE_DIR}
  COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target all
  COMMENT "Switch CMAKE_BUILD_TYPE to Release"
  )

###############################
## LIBS
set(GMP_LIBRARIES gmp gmpxx)
if (MSVC)
	set(GMP_INCLUDE_DIR "${CMAKE_BINARY_DIR}/packages/libgmp_vc120.5.1.3.2/build/native/include")
	SET(MPIR_LIB "${CMAKE_BINARY_DIR}/packages/libgmp_vc120.5.1.3.2/build/native/bin/mpir-x86-v120-mt-s-5_1_3_2.lib")
	SET(MPIRXX_LIB "${CMAKE_BINARY_DIR}/packages/libgmp_vc120.5.1.3.2/build/native/bin/mpirxx-x86-v120-mt-s-5_1_3_2.lib")
	set(GMP_LIBRARIES "${MPIR_LIB}" "${MPIRXX_LIB}")
	include_directories(${GMP_INCLUDE_DIR})
else ()
	set(GMP_LIBRARIES gmp gmpxx)
endif ()

###############################
## COMPILER FLAGS
if (${CMAKE_CXX_COMPILER_ID} MATCHES "GNU" OR ${CMAKE_CXX_COMPILER_ID} MATCHES "INTEL")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe -Wall -std=c++11")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -O0")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -fopenmp -flto -Ofast -march=native")
elseif (${CMAKE_CXX_COMPILER_ID} MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe -Wall -std=c++11")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -O0")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -fopenmp -Ofast -march=native")
endif ()

###############################
## SOURCE FILES
set(COMMON_FILES src/include/config.hh src/include/bigint.hpp
    src/include/integer.hpp src/include/util.hpp)

set(RSAOAEP_FILES src/include/rsa.hpp src/include/oaep.hpp
    src/include/sha3.hpp src/securesharing.hh)

###############################
## OBJECT FILES
add_library(bigint OBJECT src/bigint.cc src/include/config.hh src/include/bigint.hpp)
add_library(util OBJECT src/util.cc src/include/util.hpp)
add_library(aes OBJECT src/aes.cc src/include/aes.hpp src/include/integer.hpp)
add_library(securesharing OBJECT src/securesharing.cc src/securesharing.hh ${COMMON_FILES} ${RSAOAEP_FILES})

###############################
## EXECUTABLE FILES
add_executable(rsa_genkey src/rsa_genkey.cc src/include/rsa.hpp
    src/include/primegen.hpp ${COMMON_FILES} 
    $<TARGET_OBJECTS:bigint> $<TARGET_OBJECTS:util>)

add_executable(encrypt src/encrypt.cc src/file_encrypt.cc src/file_decrypt.hh
    src/securesharing.hh src/include/aes.hpp ${RSAOAEP_FILES}
    ${COMMON_FILES}
    $<TARGET_OBJECTS:securesharing> $<TARGET_OBJECTS:aes>
    $<TARGET_OBJECTS:bigint> $<TARGET_OBJECTS:util>)

add_executable(decrypt src/decrypt.cc src/file_decrypt.cc src/file_decrypt.hh
    src/securesharing.hh src/include/aes.hpp ${RSAOAEP_FILES}
    ${COMMON_FILES}
    $<TARGET_OBJECTS:securesharing> $<TARGET_OBJECTS:aes>
    $<TARGET_OBJECTS:bigint>)


target_link_libraries(rsa_genkey ${GMP_LIBRARIES})
target_link_libraries(encrypt ${GMP_LIBRARIES})
target_link_libraries(decrypt ${GMP_LIBRARIES})
