/*
 * HXTP Embedded SDK v1.0
 * ESP32 Platform — Implementation
 *
 * NTP synchronization using ESP-IDF SNTP.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifdef ESP32

#include "hxtp_platform_esp32.h"
#include <esp_sntp.h>
#include <cstring>

namespace hxtp {
namespace platform {

bool esp32_sync_time(const char* ntp_server, uint32_t timeout_ms) {
    /* Configure SNTP */
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, ntp_server);
    esp_sntp_init();
#else
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, const_cast<char*>(ntp_server));
    sntp_init();
#endif

    /* Wait for sync */
    uint32_t elapsed = 0;
    const uint32_t poll_ms = 100;

    while (elapsed < timeout_ms) {
        struct timeval tv;
        gettimeofday(&tv, nullptr);

        /* If year is > 2020, time is synced */
        struct tm timeinfo;
        localtime_r(&tv.tv_sec, &timeinfo);
        if (timeinfo.tm_year > (2020 - 1900)) {
            return true;
        }

        vTaskDelay(pdMS_TO_TICKS(poll_ms));
        elapsed += poll_ms;
    }

    return false;
}

} /* namespace platform */
} /* namespace hxtp */

#endif /* ESP32 */
