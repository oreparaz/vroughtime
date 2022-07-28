#!/bin/bash

set -euxo pipefail

rm -f *.o

# non-clusterfuzz usage
#$CC -c tweetnacl_stub.c -o tweetnacl_stub.o
#$CC -DTESTING_VISIBILITY -Wall -Werror -g -fsanitize=address,undefined -c ../../vrt.c -o vrt_testing.o 
#$CXX -I../../ -DTARGET_FUZZ_1 -DTESTING_VISIBILITY -g -fsanitize=address,undefined,fuzzer vrt_fuzz.cc -o fuzzer1 vrt_testing.o tweetnacl_stub.o
#$CXX -I../../ -DTARGET_FUZZ_2 -DTESTING_VISIBILITY -g -fsanitize=address,undefined,fuzzer vrt_fuzz.cc -o fuzzer2 vrt_testing.o tweetnacl_stub.o
#$CXX -I../../ -DTARGET_FUZZ_3 -DTESTING_VISIBILITY -g -fsanitize=address,undefined,fuzzer vrt_fuzz.cc -o fuzzer3 vrt_testing.o tweetnacl_stub.o


# clusterfuzz usage: need to use LIB_FUZZING_ENGINE, see https://google.github.io/clusterfuzzlite/build-integration/#compilation-env
$CC $CFLAGS -c tweetnacl_stub.c -o tweetnacl_stub.o
$CC $CFLAGS -DTESTING_VISIBILITY -c ../../vrt.c -o vrt_testing.o 
$CXX $CXXFLAGS -I../../ -DTARGET_FUZZ_1 -DTESTING_VISIBILITY vrt_fuzz.cc -o fuzzer1 $LIB_FUZZING_ENGINE vrt_testing.o tweetnacl_stub.o 
$CXX $CXXFLAGS -I../../ -DTARGET_FUZZ_2 -DTESTING_VISIBILITY vrt_fuzz.cc -o fuzzer2 $LIB_FUZZING_ENGINE vrt_testing.o tweetnacl_stub.o
$CXX $CXXFLAGS -I../../ -DTARGET_FUZZ_3 -DTESTING_VISIBILITY vrt_fuzz.cc -o fuzzer3 $LIB_FUZZING_ENGINE vrt_testing.o tweetnacl_stub.o

cp fuzzer* $OUT/

# quick test to spot problems early on

#./fuzzer1 -max_total_time=10
#./fuzzer2 -max_total_time=10
#./fuzzer3 -max_total_time=10

# more comprehensive run

#./fuzzer1 -max_total_time=1000
#./fuzzer2 -max_total_time=1000
#./fuzzer3 -max_total_time=1000
