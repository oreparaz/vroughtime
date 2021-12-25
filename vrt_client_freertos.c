#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include "vrt_client.h"
#include "vrt.h"

// This client is based off
// https://github.com/espressif/esp-idf/tree/master/examples/protocols/sockets/udp_client

// buffer for vroughtime packet tx/rx.
// Must be at least 1024 bytes long and aligned to a 4-byte boundary.
// Will be shared for tx and rx.
__attribute__((aligned(4))) uint8_t vrt_buffer[VRT_QUERY_PACKET_LEN];

// NB: this code must be updatable via firmware update.
// we hardcode here the cloudflare server
// https://github.com/cloudflare/roughtime/blob/master/ecosystem.json
#define HOST_IP_ADDR "162.159.200.1" // roughtime.cloudflare.com
#define PORT 2002

// echo gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= | base64 -D | xxd -i
static uint8_t public_key_cloudflare[] = {
    0x80, 0x3e, 0xb7, 0x85, 0x28, 0xf7, 0x49, 0xc4, 0xbe, 0xc2, 0xe3, 0x9e,
    0x1a, 0xbb, 0x9b, 0x5e, 0x5a, 0xb7, 0xe4, 0xdd, 0x5c, 0xe4, 0xb6, 0xf2,
    0xfd, 0x2f, 0x93, 0xec, 0xc3, 0x53, 0x8f, 0x1a
};

static const char *TAG = "vrt_client";

static void set_time(uint64_t midp) {
    long sec = midp / 1e6;
    long usec = midp % (uint64_t)1e6;
    struct timeval tv = { .tv_sec = sec, .tv_usec = usec };
    settimeofday(&tv, NULL);

    char strftime_buf[64];
    time_t now;
    struct tm timeinfo;
    time(&now);

    setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3", 1);
    tzset();
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "The current date/time in Europe/Paris is: %s", strftime_buf);
}

extern int connected;

void udp_client_task(void *pvParameters)
{
    char host_ip[] = HOST_IP_ADDR;
    int addr_family = 0;
    int ip_protocol = 0;

    while (1) {

        while (!connected) {
            ESP_LOGE(TAG, "not connected, waiting");
            vTaskDelay(500 / portTICK_PERIOD_MS); 
        }

        struct sockaddr_in dest_addr;
        dest_addr.sin_addr.s_addr = inet_addr(HOST_IP_ADDR);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(PORT);
        addr_family = AF_INET;
        ip_protocol = IPPROTO_IP;

        int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
        if (sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
            break;
        }
        ESP_LOGI(TAG, "Socket created, sending to %s:%d", HOST_IP_ADDR, PORT);

        // prepare roughtime query
        uint8_t nonce[VRT_NONCE_SIZE];
        esp_fill_random(nonce, sizeof nonce);

        int err = vrt_make_query(nonce, sizeof(nonce), vrt_buffer, sizeof(vrt_buffer));
        if (err != VRT_SUCCESS) {
            ESP_LOGE(TAG, "vrt_make_query failed");
        }

        // send query to UDP destination
        err = sendto(sock, vrt_buffer, sizeof(vrt_buffer), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err < 0) {
            ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
            break;
        }
        ESP_LOGI(TAG, "Message sent");

        struct sockaddr_storage source_addr; // Large enough for both IPv4 or IPv6
        socklen_t socklen = sizeof(source_addr);
        int len = recvfrom(sock, vrt_buffer, sizeof(vrt_buffer), 0, (struct sockaddr *)&source_addr, &socklen);

        // Error occurred during receiving
        if (len < 0) {
            ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
            break;
        }

        // Data received
        ESP_LOGI(TAG, "Received %d bytes from %s:", len, host_ip);

        // vrt: parse response
        uint64_t out_midpoint;
        uint32_t out_radii;

        err = vrt_parse_response(nonce, 64, (uint32_t *)vrt_buffer,
                                    sizeof(vrt_buffer),
                                    public_key_cloudflare, &out_midpoint,
                                    &out_radii);

        if (err == VRT_SUCCESS) {
            ESP_LOGI(TAG, "parsed vrt midp: %" PRIu64 " radi: %u", out_midpoint, out_radii);
            set_time(out_midpoint);
        } else {
            ESP_LOGE(TAG, "vrt_parse_response failed");
        }

        if (sock != -1) {
            ESP_LOGI(TAG, "Shutting down socket and restarting...");
            shutdown(sock, 0);
            close(sock);
        }
        vTaskDelay(6 * 60 * 60 * 1000 / portTICK_PERIOD_MS); // every 6 hours
    }
    vTaskDelete(NULL);
}
