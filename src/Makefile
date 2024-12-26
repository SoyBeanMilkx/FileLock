KP_DIR = ../KernelPatch-0.11.1
KP_KERNEL_DIR = $(KP_DIR)/kernel

TOOLCHAIN_PATH ?= /home/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-elf/bin
CC = $(TOOLCHAIN_PATH)/aarch64-none-elf-gcc
LD = $(TOOLCHAIN_PATH)/aarch64-none-elf-ld

# 修改包含目录以匹配头文件需求
INCLUDE_DIRS := . \
                include \
                patch/include \
                linux/include \
                kpm/include \
                linux/arch/arm64/include \
                linux/tools/arch/arm64/include \
                hook/include         # 添加 hook.h 的目录
                
# 添加当前目录到包含路径(用于 file.h)
INCLUDE_FLAGS := -I. $(foreach dir,$(INCLUDE_DIRS),-I$(KP_KERNEL_DIR)/$(dir))

C_FILES := $(wildcard *.c)
OBJS := $(C_FILES:.c=.o)

# 编译标志
CFLAGS := -g -fno-pie -fno-stack-protector -fno-omit-frame-pointer -fno-common -O2
LDFLAGS := -r

all: mod_main.kpm

mod_main.kpm: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm *.o