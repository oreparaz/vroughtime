#include <stddef.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vrt.h"

// world's dumbest fuzzer, still finds bugs

#define CHECK(x)                                                               \
  do {                                                                         \
    int ret;                                                                   \
    if ((ret = x) != VRT_SUCCESS) {                                            \
      free(reply);                                                             \
      return (ret);                                                            \
    }                                                                          \
  } while (0)

#if TARGET_FUZZ_1

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  uint8_t nonce[64] = {0};
  uint8_t public_key[32] = {0};

  uint32_t *reply = (uint32_t *)malloc(Size);
  memcpy(reply, Data, Size);

  uint64_t out_midpoint;
  uint32_t out_radii;

  int ret = vrt_parse_response(nonce, sizeof(nonce), reply, Size, public_key,
                               &out_midpoint, &out_radii);
  free(reply);

  return 0;
}

#elif TARGET_FUZZ_2

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  vrt_blob_t b = {0};
  uint32_t *reply = (uint32_t *)malloc(Size);
  memcpy(reply, Data, Size);
  if (Size < 4) {
    free(reply);
    return 0;
  }

  uint32_t word_index = reply[0];

  uint32_t *buf = &reply[1];
  uint32_t output = 0;

  CHECK(vrt_blob_init(&b, buf, Size - 4));
  CHECK(vrt_blob_r32(&b, word_index, &output));

  free(reply);
  return 0;
}

#elif TARGET_FUZZ_3

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  vrt_blob_t b = {0};
  vrt_blob_t output_slice = {0};

  uint32_t *reply = (uint32_t *)malloc(Size);
  memcpy(reply, Data, Size);
  if (Size < 8) {
    free(reply);
    return 0;
  }

  uint32_t offset = reply[0];
  uint32_t size_slice = reply[1];
  uint32_t output_r32 = 0;

  uint32_t *buf = &reply[2];

  CHECK(vrt_blob_init(&b, buf, Size - 8));
  CHECK(vrt_blob_slice(&b, &output_slice, offset, size_slice));
  CHECK(vrt_blob_r32(&output_slice, 0, &output_r32));

  free(reply);
  return 0;
}

#endif
