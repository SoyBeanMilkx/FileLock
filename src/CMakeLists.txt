cmake_minimum_required(VERSION 3.25.2)
project(sys_security C)

set(CMAKE_C_STANDARD 99)

# 设置 KernelPatch 目录
set(KP_DIR "../KernelPatch-0.11.1")

# 设置工具链路径
set(TOOLCHAIN_PATH "/home/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-elf/bin")
set(CMAKE_C_COMPILER "${TOOLCHAIN_PATH}/aarch64-none-elf-gcc")
set(CMAKE_LINKER "${TOOLCHAIN_PATH}/aarch64-none-elf-ld")

# 设置包含目录
set(INCLUDE_DIRS
    .
    include
    patch/include
    linux/include
    kpm/include
    linux/arch/arm64/include
    linux/tools/arch/arm64/include
    hook/include
)

# 添加包含路径
include_directories(.)
foreach(dir ${INCLUDE_DIRS})
    include_directories(${KP_DIR}/kernel/${dir})
endforeach()

# 设置编译标志
set(CMAKE_C_FLAGS "-g -fno-pie -fno-stack-protector -fno-omit-frame-pointer -fno-common -O2")
set(CMAKE_SHARED_LINKER_FLAGS "-r")

# 添加源文件
file(GLOB SOURCES "*.c")

# 创建目标
add_library(mod_main SHARED ${SOURCES})

# 设置输出名称
set_target_properties(mod_main PROPERTIES
    OUTPUT_NAME "mod_main"
    SUFFIX ".kpm"
)