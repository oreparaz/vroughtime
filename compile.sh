#!/bin/bash

set -euxo pipefail

if [ "$(uname)" == "Darwin" ]; then
    CF=clang-format
    CC=clang
    CXX=clang++
elif [ "$(uname)" == "Linux" ]; then
    CF=clang-format-11
    CC=clang-12
    CXX=clang++-12
fi

$CF -i vrt.c
$CF -i vrt.h
$CF -i vrt_test.c
$CF -i vrt_fuzz.cc

rm -f *.o
$CC -c tweetnacl.c -o tweetnacl.o
$CC -c tweetnacl_stub.c -o tweetnacl_stub.o

rm -f vrt.o && $CC -Wall -Werror -g -fsanitize=address,undefined -c vrt.c -o vrt.o 
rm -f vrt_testing.o && $CC -DTESTING_VISIBILITY -Wall -Werror -g -fsanitize=address,undefined -c vrt.c -o vrt_testing.o 

rm -f vrt_test && $CC -Wall -Werror -g -fsanitize=address,undefined -o vrt_test vrt_test.c vrt.o tweetnacl.o && ./vrt_test
rm -f client && $CC -Wall -Werror -g -fsanitize=address,undefined -o client vrt_client_unix.c vrt.o tweetnacl.o && ./client

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

