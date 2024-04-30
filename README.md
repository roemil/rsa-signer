# RSA SIGNER
This is a proof of concept to get RSA key generation and SSH user authentication working on the Tkey.
RSA signer is running on a baremetal RISC-V 32 bit processor.<br>
For more information about the Tkey, see https://tillitis.se/

## Building MBEDTLS

### Prerequisites
Install https://github.com/riscv-collab/riscv-gnu-toolchain preferable to the path /opt/riscv

### Compiling MBEDTLS
First, we need to set the correct compiliation flags:
1. Set CC=clang
2. Set CFLAGS as following:
CFLAGS=-target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf -fno-builtin-putchar -nostdlib -mno-relax -flto -g -Wall -Werror=implicit-function-declaration -I../../../tkey-libs/include -I/opt/riscv/riscv32-unknown-elf/include

In the folder mbedtls do:
* make clean && make -j$nproc
* then do cd .. to go back to RSA-signer

## Building RSA-signer
* Do make clean && make
* copy the singer/app.bin to the rsa-tkey-ssh-agent

## Design choices
* Key length is set to 2048 bits and is not configurable (for now at least)
* SHA512 is used and is not configurable

## Improvements
* Update the protocol to send the data sizes before sending the data
* Make hash algorithm and key sizes configurable.