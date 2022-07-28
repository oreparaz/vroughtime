#!/bin/bash

set -euxo pipefail

cbmc vrt_cbmc_harness.c ../../vrt.c \
    --function vrt_cbmc_harness \
    --unwind 1 \
    --bounds-check \
    --pointer-check
