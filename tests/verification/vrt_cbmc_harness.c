#include "../../vrt.h"

#define CHECK(x)                                                               \
  do {                                                                         \
    int ret;                                                                   \
    if ((ret = x) != VRT_SUCCESS) {                                            \
      return (ret);                                                            \
    }                                                                          \
  } while (0)

#define CHECK_TRUE(x, errorcode)                                               \
  do {                                                                         \
    if (!(x))                                                                  \
      return (errorcode);                                                      \
  } while (0)

#define CHECK_NOT_NULL(x) CHECK_TRUE((x) != NULL, VRT_ERROR_NULL_ARGUMENT)

#define RECV_BUFFER_LEN 1024

void vrt_cbmc_harness(void) {
	uint8_t nonce_sent[VRT_NONCE_SIZE];
	uint8_t reply[RECV_BUFFER_LEN];
	uint8_t pk[32];
	uint64_t *out_midp;
	uint32_t *out_radii;

	CHECK(vrt_parse_response(nonce_sent, sizeof(nonce_sent),
                              reply, sizeof(reply), pk,
                              out_midp, out_radii));
}
