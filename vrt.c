// vroughtime: compact rough time client implementation
//
// https://github.com/oreparaz/vroughtime
//
// (c) 2021 Oscar Reparaz <firstname.lastname@esat.kuleuven.be>

#include <stdbool.h>
#include <string.h>

#include "tweetnacl.h"
#include "vrt.h"

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

VISIBILITY_ONLY_TESTING vrt_ret_t vrt_blob_init(vrt_blob_t *b, uint32_t *data,
                                                uint32_t size) {
  CHECK_NOT_NULL(b);
  CHECK_NOT_NULL(data);

  // passed size must be multiple of 4-bytes
  if (size & 3) {
    return VRT_ERROR_MALFORMED;
  }
  *b = (vrt_blob_t){.data = data, .size = size};
  return VRT_SUCCESS;
}

VISIBILITY_ONLY_TESTING vrt_ret_t vrt_blob_r32(vrt_blob_t *b,
                                               uint32_t word_index,
                                               uint32_t *out) {
  CHECK_NOT_NULL(b);
  CHECK_NOT_NULL(out);

  // mind integer overflow if this condition was written as 4*word_index >=
  // b->size instead
  if (word_index >= b->size / 4) {
    return VRT_ERROR_MALFORMED;
  }

  *out = b->data[word_index];
  return VRT_SUCCESS;
}

static vrt_ret_t vrt_blob_r64(vrt_blob_t *b, uint32_t word_index,
                              uint64_t *out) {
  CHECK_NOT_NULL(b);
  CHECK_NOT_NULL(out);

  uint32_t lo = 0;
  uint32_t hi = 0;
  CHECK(vrt_blob_r32(b, word_index, &lo));
  CHECK(vrt_blob_r32(b, word_index + 1, &hi));
  *out = (uint64_t)lo + ((uint64_t)hi << 32);
  return VRT_SUCCESS;
}

VISIBILITY_ONLY_TESTING vrt_ret_t vrt_blob_slice(const vrt_blob_t *b,
                                                 vrt_blob_t *slice,
                                                 uint32_t offset,
                                                 uint32_t size) {
  CHECK_NOT_NULL(b);
  CHECK_NOT_NULL(slice);

  uint32_t slice_end = 4 * offset + size;
  uint64_t slice_end64 =
      4 * (uint64_t)offset + (uint64_t)size; // can't overflow

  if (slice_end64 != slice_end) {
    return VRT_ERROR_MALFORMED;
  }

  if (slice_end > b->size) {
    return VRT_ERROR_MALFORMED;
  }

  slice->data = &b->data[offset];
  slice->size = size;
  return VRT_SUCCESS;
}

static vrt_ret_t vrt_get_tag(vrt_blob_t *out, vrt_blob_t *in,
                             uint32_t tag_wanted) {
  uint32_t num_tags = 0;
  uint32_t tag_read = 0;
  uint32_t offset = 0;
  uint32_t tag_end = 0;

  // arithmetic in vrt_get_tag can overflow

  CHECK(vrt_blob_r32(in, 0, &num_tags));
  for (int i = 0; i < num_tags; i++) {
    CHECK(vrt_blob_r32(in, i + num_tags, &tag_read));
    if (tag_wanted == tag_read) {
      CHECK(vrt_blob_r32(in, i, &offset));
      if (i == 0) {
        offset = 0;
      }
      if (i == (num_tags - 1)) {
        tag_end = in->size - 8 * num_tags;
      } else {
        CHECK(vrt_blob_r32(in, i + 1, &tag_end));
      }

      CHECK(vrt_blob_slice(in, out, (2 * num_tags) + offset / 4,
                           tag_end - offset));
      return VRT_SUCCESS;
    }
  }
  return VRT_ERROR_TAG_NOT_FOUND;
}

static vrt_ret_t vrt_verify_dele(vrt_blob_t *cert_sig, vrt_blob_t *cert_dele,
                                 uint8_t *root_public_key) {
  uint8_t msg[CERT_SIG_SIZE + CERT_DELE_SIZE + CONTEXT_CERT_SIZE] = {0};

  CHECK_TRUE(cert_sig->size == CERT_SIG_SIZE, VRT_ERROR_WRONG_SIZE);
  CHECK_TRUE(cert_dele->size == CERT_DELE_SIZE, VRT_ERROR_WRONG_SIZE);

  memcpy(&msg, cert_sig->data, cert_sig->size);
  memcpy(msg + cert_sig->size, CONTEXT_CERT, CONTEXT_CERT_SIZE);
  memcpy(msg + cert_sig->size + CONTEXT_CERT_SIZE, cert_dele->data,
         cert_dele->size);

  size_t msg_size = cert_sig->size + cert_dele->size + CONTEXT_CERT_SIZE;
  uint8_t plaintext[sizeof msg] = {0};
  unsigned long long unsigned_message_len;

  int ret = crypto_sign_open(plaintext, &unsigned_message_len, msg, msg_size,
                             root_public_key);
  return (ret == 0) ? VRT_SUCCESS : VRT_ERROR_DELE;
}

static vrt_ret_t vrt_verify_pubk(vrt_blob_t *sig, vrt_blob_t *srep,
                                 uint32_t *pubk) {
  uint8_t msg[CERT_SIG_SIZE + CONTEXT_RESP_SIZE + MAX_SREP_SIZE] = {0};

  CHECK_TRUE(sig->size == CERT_SIG_SIZE, VRT_ERROR_WRONG_SIZE);
  CHECK_TRUE(srep->size == MAX_SREP_SIZE || srep->size == ALTERNATE_SREP_SIZE,
             VRT_ERROR_WRONG_SIZE);

  memcpy(&msg, sig->data, sig->size);
  memcpy(msg + sig->size, CONTEXT_RESP, CONTEXT_RESP_SIZE);
  memcpy(msg + sig->size + CONTEXT_RESP_SIZE, srep->data, srep->size);
  size_t msg_size = sig->size + srep->size + CONTEXT_RESP_SIZE;

  uint8_t plaintext[sizeof msg] = {0};
  unsigned long long unsigned_message_len;

  int ret = crypto_sign_open(plaintext, &unsigned_message_len, msg, msg_size,
                             (uint8_t *)pubk);
  return (ret == 0) ? VRT_SUCCESS : VRT_ERROR_PUBK;
}

static vrt_ret_t vrt_hash_leaf(uint8_t *out, const uint8_t *in) {
  uint8_t msg[VRT_NONCE_SIZE + 1 /* domain separation label */];
  msg[0] = VRT_DOMAIN_LABEL_LEAF;
  memcpy(msg + 1, in, VRT_NONCE_SIZE);
  crypto_hash_sha512(out, msg, sizeof msg);
  return VRT_SUCCESS;
}

static vrt_ret_t vrt_hash_node(uint8_t *out, const uint8_t *left,
                               const uint8_t *right, int nodesize) {
  uint8_t msg[2 * VRT_NODESIZE_MAX + 1 /* domain separation label */];
  msg[0] = VRT_DOMAIN_LABEL_NODE;
  memcpy(msg + 1, left, nodesize);
  memcpy(msg + 1 + nodesize, right, nodesize);
  crypto_hash_sha512(out, msg, 2 * nodesize + 1);
  return VRT_SUCCESS;
}

static vrt_ret_t vrt_verify_nonce(vrt_blob_t *srep, vrt_blob_t *indx,
                                  vrt_blob_t *path, uint8_t *sent_nonce) {
  vrt_blob_t root;
  CHECK(vrt_get_tag(&root, srep, VRT_TAG_ROOT));

  uint8_t hash[VRT_HASHOUT_SIZE] = {0};

  CHECK_TRUE(srep->size == MAX_SREP_SIZE || srep->size == ALTERNATE_SREP_SIZE,
             VRT_ERROR_WRONG_SIZE);

  CHECK(vrt_hash_leaf(hash, sent_nonce));

  // IETF version has node size 32 bytes,
  // original version has 64-byte nodes.
  const int nodesize =
      srep->size == MAX_SREP_SIZE ? VRT_NODESIZE_MAX : VRT_NODESIZE_ALTERNATE;
  uint32_t index = 0;
  uint32_t offset = 0;
  vrt_blob_t path_chunk = {0};

  CHECK(vrt_blob_r32(indx, 0, &index));

  for (int i = 0; i < 32; i++) {
    // we're abusing a bit here vrt_blob_slice:
    // we're relying on oob access returning != VRT_SUCCESS to detect
    // there's nothing left in path
    if (vrt_blob_slice(path, &path_chunk, offset, nodesize) != VRT_SUCCESS) {
      break;
    }

    if (index & (1UL << i)) {
      CHECK(vrt_hash_node(hash, (uint8_t *)path_chunk.data, hash, nodesize));
    } else {
      CHECK(vrt_hash_node(hash, hash, (uint8_t *)path_chunk.data, nodesize));
    }
    offset += nodesize / 4;
  }

  CHECK_TRUE(root.size == nodesize, VRT_ERROR_WRONG_SIZE);
  return (memcmp(root.data, hash, nodesize) == 0) ? VRT_SUCCESS
                                                  : VRT_ERROR_TREE;
}

static vrt_ret_t vrt_verify_bounds(vrt_blob_t *srep, vrt_blob_t *dele,
                                   uint64_t *out_midp, uint32_t *out_radi) {
  vrt_blob_t midp = {0};
  vrt_blob_t radi = {0};
  vrt_blob_t mint = {0};
  vrt_blob_t maxt = {0};

  uint64_t min = 0;
  uint64_t max = 0;

  CHECK(vrt_get_tag(&midp, srep, VRT_TAG_MIDP));
  CHECK(vrt_get_tag(&radi, srep, VRT_TAG_RADI));
  CHECK(vrt_get_tag(&mint, dele, VRT_TAG_MINT));
  CHECK(vrt_get_tag(&maxt, dele, VRT_TAG_MAXT));

  CHECK(vrt_blob_r64(&midp, 0, out_midp));
  CHECK(vrt_blob_r32(&radi, 0, out_radi));
  CHECK(vrt_blob_r64(&mint, 0, &min));
  CHECK(vrt_blob_r64(&maxt, 0, &max));

  if (min < *out_midp && max > *out_midp) {
    return VRT_SUCCESS;
  }

  *out_midp = 0;
  *out_radi = 0;
  return VRT_ERROR_BOUNDS;
}

vrt_ret_t vrt_parse_response(uint8_t *nonce_sent, uint32_t nonce_len,
                             uint32_t *reply, uint32_t reply_len, uint8_t *pk,
                             uint64_t *out_midpoint, uint32_t *out_radii) {
  vrt_blob_t parent;
  vrt_blob_t cert = {0};
  vrt_blob_t cert_sig = {0};
  vrt_blob_t cert_dele = {0};
  vrt_blob_t srep = {0};
  vrt_blob_t pubk = {0};
  vrt_blob_t sig = {0};
  vrt_blob_t indx = {0};
  vrt_blob_t path = {0};

  CHECK_TRUE(nonce_len >= VRT_NONCE_SIZE, VRT_ERROR_WRONG_SIZE);
  CHECK(vrt_blob_init(&parent, reply, reply_len));
  CHECK(vrt_get_tag(&srep, &parent, VRT_TAG_SREP));
  CHECK(vrt_get_tag(&sig, &parent, VRT_TAG_SIG));
  CHECK(vrt_get_tag(&cert, &parent, VRT_TAG_CERT));
  CHECK(vrt_get_tag(&cert_sig, &cert, VRT_TAG_SIG));
  CHECK(vrt_get_tag(&cert_dele, &cert, VRT_TAG_DELE));
  CHECK(vrt_get_tag(&pubk, &cert_dele, VRT_TAG_PUBK));
  CHECK(vrt_get_tag(&indx, &parent, VRT_TAG_INDX));
  CHECK(vrt_get_tag(&path, &parent, VRT_TAG_PATH));

  CHECK(vrt_verify_dele(&cert_sig, &cert_dele, pk));
  CHECK_TRUE(pubk.size == 32, VRT_ERROR_MALFORMED);
  CHECK(vrt_verify_pubk(&sig, &srep, pubk.data));
  CHECK(vrt_verify_nonce(&srep, &indx, &path, nonce_sent));
  CHECK(vrt_verify_bounds(&srep, &cert_dele, out_midpoint, out_radii));

  return VRT_SUCCESS;
}

static const uint8_t query_header[] = {0x02, 0x00, 0x00, 0x00, 0x40, 0x00,
                                       0x00, 0x00, 0x4e, 0x4f, 0x4e, 0x43,
                                       0x50, 0x41, 0x44, 0xff};

vrt_ret_t vrt_make_query(uint8_t *nonce, uint32_t nonce_len, uint8_t *out_query,
                         uint32_t out_query_len) {
  CHECK_TRUE(nonce_len >= VRT_NONCE_SIZE, VRT_ERROR_WRONG_SIZE);
  CHECK_TRUE(out_query_len >= 1024, VRT_ERROR_WRONG_SIZE);
  memset(out_query, 0, out_query_len);
  memcpy(out_query, query_header, sizeof query_header);
  memcpy(out_query + sizeof query_header, nonce, VRT_NONCE_SIZE);

  return VRT_SUCCESS;
}
