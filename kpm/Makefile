KP_DIR ?= ../KernelPatch
KERNEL_DIR ?= $(KP_DIR)/kernel

SDK_DIR ?= $(ANDROID_SDK_ROOT)
ifeq ($(strip $(SDK_DIR)),)
SDK_DIR := $(ANDROID_HOME)
endif
ifeq ($(strip $(SDK_DIR)),)
SDK_DIR := /opt/homebrew/share/android-commandlinetools
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
TOOLCHAIN_HOST ?= darwin-x86_64
else
TOOLCHAIN_HOST ?= linux-x86_64
endif

NDK_DIR ?= $(shell find "$(SDK_DIR)/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1)
TOOLCHAIN ?= $(NDK_DIR)/toolchains/llvm/prebuilt/$(TOOLCHAIN_HOST)/bin

CC := $(TOOLCHAIN)/aarch64-linux-android21-clang
LD := $(CC)

INCLUDE = -I$(KERNEL_DIR)/include \
          -I$(KERNEL_DIR)/patch/include \
          -I$(KERNEL_DIR)/linux/include \
          -I$(KERNEL_DIR)/linux/include/uapi \
          -I$(KERNEL_DIR)/linux/arch/arm64/include \
          -I$(KERNEL_DIR)/linux/tools/arch/arm64/include \
          -I$(KERNEL_DIR)/linux/arch/arm64/include/uapi

CFLAGS = -Wall -O2 -fno-pic -fno-stack-protector \
         -nostdlib -nostdinc -ffreestanding \
         -fno-builtin \
         -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove -fno-builtin-memcmp \
         -mgeneral-regs-only \
         $(INCLUDE)

LDFLAGS = -r

TARGET = z9null_monitor.kpm

all: check-env $(TARGET)

check-env:
	@test -d "$(KERNEL_DIR)" || (echo "Missing KernelPatch kernel dir: $(KERNEL_DIR)" >&2; exit 1)
	@test -x "$(CC)" || (echo "Missing Android NDK clang: $(CC)" >&2; exit 1)

$(TARGET): src/z9null_monitor.c
	$(CC) $(CFLAGS) -c $< -o z9null_monitor.o
	$(LD) -nostdlib $(LDFLAGS) z9null_monitor.o -o $@
	rm -f z9null_monitor.o

clean:
	rm -f $(TARGET) z9null_monitor.o

.PHONY: all check-env clean
