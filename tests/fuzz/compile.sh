#!/bin/bash

set -euxo pipefail

CC=clang

rm -f *.o

$CC -c tweetnacl_stub.c -o tweetnacl_stub.o
$CC -DTESTING_VISIBILITY -Wall -Werror -g -fsanitize=address,undefined -c ../../vrt.c -o vrt_testing.o 

for TARGET_FUZZ in TARGET_FUZZ_1 TARGET_FUZZ_2 TARGET_FUZZ_3; do
    rm -f fuzz && $CXX -D$TARGET_FUZZ -DTESTING_VISIBILITY -g -fsanitize=address,undefined,fuzzer vrt_fuzz.cc -o fuzz vrt_testing.o tweetnacl_stub.o

    # very quick test to spot problems early on
    ./fuzz -max_total_time=10
done

for TARGET_FUZZ in TARGET_FUZZ_1 TARGET_FUZZ_2 TARGET_FUZZ_3; do
    rm -f fuzz && $CXX -D$TARGET_FUZZ -DTESTING_VISIBILITY -g -fsanitize=address,undefined,fuzzer vrt_fuzz.cc -o fuzz vrt_testing.o tweetnacl_stub.o

    # more comprehensive run
    ./fuzz -max_total_time=1000
done

