#!/bin/bash

VERSION=2.36
LIBC_NAME=libc.so.6
LD_NAME=ld-linux-x86-64.so.2

gcc pwn.c -o pwn -g

chmod 777 ${LIBC_NAME}
chmod 777 ${LD_NAME}

patchelf --replace-needed libc.so.6 ./${LIBC_NAME} ./pwn
patchelf --set-interpreter ./${LD_NAME} ./pwn
