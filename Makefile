# Check for OS, if not macos assume linux
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	shasum = shasum -a 512
else
	shasum = sha512sum
endif

OBJCOPY ?= llvm-objcopy

P := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
LIBDIR ?= $(P)/../tkey-libs

CC = clang

INCLUDE=$(LIBDIR)/include

# If you want libcommon's qemu_puts() et cetera to output something on our QEMU
# debug port, use -DQEMU_DEBUG below
CFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany \
   -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf \
   -fno-builtin-putchar -nostdlib -mno-relax -flto -g \
   -Wall -Werror=implicit-function-declaration \
   -I $(INCLUDE) -I $(LIBDIR) -I../tkey-libs -I mbedtls/include -I/opt/riscv/riscv32-unknown-elf/include #-DTKEY_SIGNER_APP_NO_TOUCH=yes -DQEMU_DEBUG 

ifneq ($(TKEY_SIGNER_APP_NO_TOUCH),)
CFLAGS := $(CFLAGS) -DTKEY_SIGNER_APP_NO_TOUCH
endif

AS = clang
ASFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany -mno-relax

LDFLAGS=-T $(LIBDIR)/app.lds -L $(LIBDIR) -lcommon -lcrt0 -L mbedtls/library -L /opt/riscv/lib/gcc/riscv32-unknown-elf/13.2.0/ -lgcc -L  /opt/riscv/riscv32-unknown-elf/lib/ -lc


.PHONY: all
all: signer/app.bin

# Turn elf into bin for device
%.bin: %.elf
	$(OBJCOPY) --input-target=elf32-littleriscv --output-target=binary $^ $@
	chmod a-x $@

show-%-hash: %/app.bin
	@echo "Device app digest:"
	@sha512sum $$(dirname $^)/app.bin


.PHONY: check
check:
	clang-tidy -header-filter=.* -checks=cert-* signer/*.[ch] -- $(CFLAGS)

# Simple ed25519 signer app
SIGNEROBJS=signer/main.o signer/app_proto.o mbedtls/library/rsa.o
signer/app.elf: $(SIGNEROBJS)
	$(CC) $(CFLAGS) $(SIGNEROBJS) $(LDFLAGS) -L $(LIBDIR)/monocypher -lmonocypher -I $(LIBDIR) -L mbedtls/library -lmbedcrypto -o $@
$(SIGNEROBJS): $(INCLUDE)/tkey/tk1_mem.h signer/app_proto.h

.PHONY: clean
clean:
	rm -f signer/app.bin signer/app.elf $(SIGNEROBJS)

# Uses ../.clang-format
FMTFILES=signer/*.[ch]

.PHONY: fmt
fmt:
	clang-format --dry-run --ferror-limit=0 $(FMTFILES)
	clang-format --verbose -i $(FMTFILES)
.PHONY: checkfmt
checkfmt:
	clang-format --dry-run --ferror-limit=0 --Werror $(FMTFILES)
