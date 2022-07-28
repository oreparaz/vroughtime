#!/bin/bash

set -euxo pipefail

CC=clang

rm -f *.o

$CC -c ../../tweetnacl.c -o tweetnacl.o
$CC -DTESTING_VISIBILITY -Wall -Werror -g -fsanitize=address,undefined -c ../../vrt.c -o vrt.o 
$CC -I ../../ -Wall -Werror -g -fsanitize=address,undefined -o vrt_test vrt_test.c vrt.o tweetnacl.o && ./vrt_test
