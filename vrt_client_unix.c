#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>

#include "vrt.h"

//#define PORT 2002
//#define HOST "roughtime.sandbox.google.com"
#define PORT 2002
#define HOST "roughtime.cloudflare.com"
#define RECV_BUFFER_LEN 1024

// https://github.com/cloudflare/roughtime/blob/master/ecosystem.json

// echo etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ= | base64 -D | xxd -i
static uint8_t public_key_google[] = {
    0x7a, 0xd3, 0xda, 0x68, 0x8c, 0x5c, 0x04, 0xc6, 0x35, 0xa1, 0x47,
    0x86, 0xa7, 0x0b, 0xcf, 0x30, 0x22, 0x4c, 0xc2, 0x54, 0x55, 0x37,
    0x1b, 0xf9, 0xd4, 0xa2, 0xbf, 0xb6, 0x4b, 0x68, 0x25, 0x34};

// echo gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= | base64 -D | xxd -i
static uint8_t public_key_cloudflare[] = {
    0x80, 0x3e, 0xb7, 0x85, 0x28, 0xf7, 0x49, 0xc4, 0xbe, 0xc2, 0xe3, 0x9e,
    0x1a, 0xbb, 0x9b, 0x5e, 0x5a, 0xb7, 0xe4, 0xdd, 0x5c, 0xe4, 0xb6, 0xf2,
    0xfd, 0x2f, 0x93, 0xec, 0xc3, 0x53, 0x8f, 0x1a
};

#define CHECK(x)                                                               \
  do {                                                                         \
    int ret;                                                                   \
    if ((ret = x) != VRT_SUCCESS) {                                            \
      return (ret);                                                            \
    }                                                                          \
  } while (0)

int prepare_socket(void)
{
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  assert(sockfd >= 0);
  return sockfd;
}

void prepare_servaddr(struct sockaddr_in *servaddr)
{
  struct hostent *he;
  he = gethostbyname(HOST);
  assert(he != NULL);

  bzero((char *)servaddr, sizeof(*servaddr));

  char **ip_addr;
  memcpy(&ip_addr, &(he->h_addr_list[0]), sizeof(void *));
  memcpy(&servaddr->sin_addr.s_addr, ip_addr, sizeof(struct in_addr));

  servaddr->sin_family = AF_INET;
  servaddr->sin_port = htons(PORT);
}

int main(int argc, char **argv) {
  uint32_t recv_buffer[RECV_BUFFER_LEN / 4] = {0};
  uint8_t query[VRT_QUERY_PACKET_LEN] = {0};
  struct sockaddr_in servaddr;
  
  int sockfd = prepare_socket();
  prepare_servaddr(&servaddr);

  /* prepare query */
  uint8_t nonce[VRT_NONCE_SIZE] = "preferably a random byte buffer";
  CHECK(vrt_make_query(nonce, 64, query, sizeof query));

  /* send query */
  int n = sendto(sockfd, (const char *)query, sizeof query, 0,
             (const struct sockaddr *)&servaddr, sizeof(servaddr));

  /* receive packet */
  assert(n==sizeof query);
  do {
    n = recv(sockfd, recv_buffer, (sizeof recv_buffer) * sizeof recv_buffer[0], 0 /* flags */);
  } while (n == -1 && errno == EINTR);

  /* parse response */
  uint64_t out_midpoint;
  uint32_t out_radii;

  CHECK(vrt_parse_response(nonce, 64, recv_buffer,
                            sizeof recv_buffer * sizeof recv_buffer[0],
                            //public_key_google, &out_midpoint,
                            public_key_cloudflare, &out_midpoint,
                            &out_radii));
  printf("midp %" PRIu64 " radi %u\n", out_midpoint, out_radii);
  close(sockfd);

  (void)public_key_google;
  (void)public_key_cloudflare;

  return 0;
}
